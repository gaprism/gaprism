"""The technology ruleset: its integrity, and the dates of what is old."""

from __future__ import annotations

import datetime
import re

import pytest

from app.checks import tech_rules
from app.checks.tech_rules import (
    BY_KEY,
    CATEGORIES,
    CATEGORY_ORDER,
    FLAGGED_HOSTS,
    SERVICE_CATEGORIES,
    TECHNOLOGIES,
    assess_version,
    parse_version,
)

TODAY = datetime.date(2026, 10, 7)


def test_every_entry_has_a_unique_key_a_known_category_and_a_name() -> None:
    keys = [tech.key for tech in TECHNOLOGIES]
    assert len(keys) == len(set(keys)) and set(BY_KEY) == set(keys)
    assert {tech.category for tech in TECHNOLOGIES} <= {key for key, _name in CATEGORIES}
    assert all(tech.name and re.fullmatch(r"[a-z0-9_]+", tech.key) for tech in TECHNOLOGIES)
    assert list(CATEGORY_ORDER) == [key for key, _name in CATEGORIES]
    assert SERVICE_CATEGORIES <= set(CATEGORY_ORDER)


def test_every_pattern_compiles_and_every_name_is_written_the_way_it_is_compared() -> None:
    for tech in TECHNOLOGIES:
        patterns = [
            *(pattern for _name, pattern in tech.headers),
            *tech.cookies,
            *tech.generator,
            *tech.paths,
            *tech.version,
        ]
        for pattern in patterns:
            re.compile(pattern)
        assert all(name == name.lower() for name, _pattern in tech.headers), tech.key
        for suffix in (*tech.hosts, *tech.owns, *tech.cnames):
            assert suffix == suffix.lower() and not suffix.startswith(".") and "." in suffix, (
                tech.key,
                suffix,
            )
        for pattern in tech.version:
            assert re.compile(pattern).groups >= 1, (tech.key, pattern)  # the version is group 1


def test_an_entry_without_evidence_exists_only_because_another_one_implies_it() -> None:
    implied = {key for tech in TECHNOLOGIES for key in tech.implies}
    assert implied <= set(BY_KEY)
    for tech in TECHNOLOGIES:
        has_evidence = any(
            (
                tech.headers,
                tech.cookies,
                tech.generator,
                tech.hosts,
                tech.paths,
                tech.markers,
                tech.networks,
                tech.cnames,
            )
        )
        assert has_evidence or tech.key in implied, tech.key


def test_what_implies_what_has_no_cycle() -> None:
    def reach(key: str, seen: tuple[str, ...] = ()) -> None:
        assert key not in seen, f"cycle through {key}"
        for implied in BY_KEY[key].implies:
            reach(implied, (*seen, key))

    for tech in TECHNOLOGIES:
        reach(tech.key)


def test_the_network_names_are_the_ones_the_ip_check_uses() -> None:
    from app.service.geo import networks

    names = {
        hint.name for hint in (*networks.ASN_HINTS.values(), *(h for _s, h in networks.NAME_HINTS))
    }
    for tech in TECHNOLOGIES:
        for network in tech.networks:
            assert network in names, (tech.key, network)


def test_the_flagged_hosts_are_plain_domains_with_a_reason() -> None:
    assert "polyfill.io" in FLAGGED_HOSTS
    for host, reason in FLAGGED_HOSTS.items():
        assert host == host.lower() and "." in host and reason


def test_an_old_dependency_of_the_ruleset_names_a_product_of_it() -> None:
    for key in (*tech_rules.RELEASES, *tech_rules.OLD):
        assert key in BY_KEY, key


# ------------------------------------------------------------------------------ old versions


@pytest.mark.parametrize(
    ("key", "version", "reason"),
    [
        ("php", "5.6.40", "end_of_life"),
        ("php", "7.4.33", "end_of_life"),
        ("php", "8.0.30", "end_of_life"),
        ("php", "8.1.2", "end_of_life"),  # security support ended on 2025-12-31
        ("apache", "2.2.34", "end_of_life"),
        ("apache", "2.0.52", "end_of_life"),
        ("iis", "6.0", "end_of_life"),
        ("iis", "8.5", "end_of_life"),
        ("angularjs", "1.8.2", "end_of_life"),
        ("bootstrap", "3.4.1", "end_of_life"),
        ("bootstrap", "4.6.2", "end_of_life"),
        ("python", "2.7.18", "end_of_life"),
        ("drupal", "7.98", "end_of_life"),
        ("joomla", "3.10.12", "end_of_life"),
        ("jquery", "1.12.4", "known_vulnerable"),
        ("jquery", "3.4.1", "known_vulnerable"),
    ],
)
def test_a_version_past_its_support_or_with_known_flaws_is_old(
    key: str, version: str, reason: str
) -> None:
    verdict = assess_version(key, version, TODAY)
    assert verdict is not None and verdict["reason"] == reason and verdict["detail"]


@pytest.mark.parametrize(
    ("key", "version"),
    [
        ("php", "8.2.20"),  # supported until 2026-12-31: the day matters
        ("php", "8.3.1"),
        ("php", "9.0.0"),  # a line the table does not know is not called old
        ("apache", "2.4.57"),
        ("iis", "10.0"),
        ("angularjs", "2.0.0"),
        ("bootstrap", "5.3.0"),
        ("jquery", "3.5.0"),
        ("jquery", "3.7.1"),
        ("python", "3.12.1"),
        ("drupal", "10.2"),
        ("joomla", "4.4.2"),
        ("nginx", "1.0.0"),  # no dates for it: nothing is said
        ("not-a-product", "1.0"),
    ],
)
def test_a_current_version_or_one_the_ruleset_has_no_dates_for_is_not_called_old(
    key: str, version: str
) -> None:
    assert assess_version(key, version, TODAY) is None


def test_the_day_decides_whether_a_release_has_ended() -> None:
    assert assess_version("php", "8.2.1", datetime.date(2026, 12, 31)) is None
    assert assess_version("php", "8.2.1", datetime.date(2027, 1, 1)) is not None


@pytest.mark.parametrize("version", [None, "", "abc", "v", "."])
def test_no_version_or_one_that_cannot_be_read_says_nothing(version: str | None) -> None:
    assert assess_version("php", version, TODAY) is None


def test_versions_are_read_as_numbers_not_as_text() -> None:
    assert parse_version("8.1.2") == (8, 1, 2)
    assert parse_version("10.0") == (10, 0)
    assert parse_version("2.4.57 (Debian)") == (2, 4, 57)
    assert parse_version("1.2.3.4.5") == (1, 2, 3, 4)
    assert parse_version("x") is None
    assert assess_version("jquery", "3.10.0", TODAY) is None  # 3.10 is newer than 3.5, not older
