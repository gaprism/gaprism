"""The takeover ruleset: its integrity, how targets are matched, how text is compared."""

from __future__ import annotations

import datetime

import pytest

from app.checks import takeover_services
from app.checks.takeover_services import (
    BY_KEY,
    SERVICES,
    Service,
    normalise,
    services_for,
)

PAGE = [service for service in SERVICES if service.how == "page"]
DNS = [service for service in SERVICES if service.how == "dns"]


def test_every_service_has_a_unique_key_and_a_name() -> None:
    keys = [service.key for service in SERVICES]
    assert len(keys) == len(set(keys)) and set(BY_KEY) == set(keys)
    assert all(service.name for service in SERVICES)


def test_the_ruleset_names_its_source_and_its_licence() -> None:
    """CC BY 4.0 asks for the creator, the licence and a note on the changes: keep them here."""
    doc = takeover_services.__doc__ or ""
    assert "can-i-take-over-xyz" in doc and "EdOverflow" in doc
    assert "CC BY 4.0" in doc and "Changes made here" in doc
    assert takeover_services.SOURCE_URL.startswith("https://github.com/EdOverflow/")
    assert takeover_services.LICENCE_URL == "https://creativecommons.org/licenses/by/4.0/"
    assert datetime.date.fromisoformat(takeover_services.CHECKED_ON)


@pytest.mark.parametrize("service", SERVICES, ids=lambda s: s.key)
def test_a_service_says_which_targets_belong_to_it(service: Service) -> None:
    assert service.suffixes or service.pattern is not None
    for suffix in service.suffixes:
        assert suffix == suffix.lower() and not suffix.startswith(".") and not suffix.endswith(".")
        assert "." in suffix  # never a bare top-level domain
        assert service.matches(f"wdd-1.{suffix}") and service.matches(suffix)


@pytest.mark.parametrize("service", PAGE, ids=lambda s: s.key)
def test_a_page_service_has_specific_signatures_and_the_status_they_come_with(
    service: Service,
) -> None:
    assert service.signatures and service.statuses
    for signature in service.signatures:
        # specific enough not to appear on an ordinary page (a bare "Not found" would)
        assert len(normalise(signature)) >= 14, signature
    assert all(isinstance(status, int) and 400 <= status < 500 for status in service.statuses)


@pytest.mark.parametrize("service", DNS, ids=lambda s: s.key)
def test_a_dns_service_has_no_page_to_compare(service: Service) -> None:
    assert not service.signatures and service.suffixes


def test_claims_are_open_or_conditional() -> None:
    assert {service.claim for service in SERVICES} <= {"open", "conditional"}


@pytest.mark.parametrize(
    ("target", "matches"),
    [
        ("vendor.github.io", True),
        ("github.io", True),
        ("VENDOR.GitHub.IO.", True),  # DNS names are case-insensitive and may end in a dot
        ("deep.name.vendor.github.io", True),
        ("evilgithub.io", False),  # a longer name that merely ends in the same letters
        ("github.io.evil.example", False),
        ("github.com", False),
        ("vendor.example", False),
    ],
)
def test_a_target_belongs_to_a_service_by_its_labels_not_by_its_letters(
    target: str, matches: bool
) -> None:
    assert BY_KEY["github_pages"].matches(target) is matches


@pytest.mark.parametrize(
    "target",
    [
        "s3.amazonaws.com",
        "bucket.s3.amazonaws.com",
        "shop.vendor.example.s3.amazonaws.com",
        "bucket.s3.eu-west-1.amazonaws.com",
        "bucket.s3-eu-west-1.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "bucket.s3-website.eu-west-1.amazonaws.com",
        "bucket.s3.dualstack.us-east-1.amazonaws.com",
    ],
)
def test_the_endpoints_of_s3_are_recognised(target: str) -> None:
    assert [service.key for service in services_for(target)] == ["aws_s3"]


@pytest.mark.parametrize(
    "target",
    [
        "ec2-1-2-3-4.compute-1.amazonaws.com",
        "web-1234.eu-west-1.elb.amazonaws.com",
        "ss3.amazonaws.com",
        "evil-s3.amazonaws.com",
        "s3.amazonaws.com.evil.example",
        "amazonaws.com",
    ],
)
def test_other_amazon_names_are_not_s3(target: str) -> None:
    assert services_for(target) == []


def test_a_target_may_belong_to_no_service_and_the_namespaces_do_not_overlap() -> None:
    assert services_for("lb-1.vendor.example") == []
    for service in SERVICES:
        for suffix in service.suffixes:
            assert [found.key for found in services_for(f"x.{suffix}")] == [service.key]


def test_text_is_compared_without_markup_entities_quotes_case_or_spacing() -> None:
    assert normalise("There isn&#39;t a  GitHub\n Pages site here.") == (
        "there isn't a github pages site here."
    )
    assert normalise("doesn\N{RIGHT SINGLE QUOTATION MARK}t exist") == "doesn't exist"
    assert normalise("\N{LEFT DOUBLE QUOTATION MARK}Not Found\N{RIGHT DOUBLE QUOTATION MARK}") == (
        '"not found"'
    )
    assert normalise("") == ""
