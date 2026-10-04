"""The advisory CDN and hosting hints."""

from __future__ import annotations

import pytest

from app.service.geo.networks import ASN_HINTS, KINDS, NAME_HINTS, hint_for


def test_a_cdn_as_number_marks_the_address_as_an_edge() -> None:
    hint = hint_for(13335)
    assert hint is not None and (hint.name, hint.kind, hint.edge) == ("Cloudflare", "cdn", True)
    assert hint_for(54113) is not None and hint_for(54113).edge is True  # type: ignore[union-attr]


def test_a_cloud_or_hosting_as_number_is_named_but_not_an_edge() -> None:
    aws, hetzner = hint_for(16509), hint_for(24940)
    assert aws is not None and (aws.kind, aws.edge) == ("cloud", False)
    assert hetzner is not None and (hetzner.kind, hetzner.edge) == ("hosting", False)


def test_a_cdn_name_in_the_cname_chain_beats_the_as_number() -> None:
    """CloudFront shares its AS numbers with EC2: only the name tells them apart."""
    by_as = hint_for(16509)
    by_name = hint_for(16509, ["d111111abcdef8.cloudfront.net"])
    assert by_as is not None and by_as.edge is False
    assert by_name is not None and (by_name.name, by_name.edge) == ("Amazon CloudFront", True)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("d1.cloudfront.net", "Amazon CloudFront"),
        ("D1.CLOUDFRONT.NET.", "Amazon CloudFront"),  # case and a final dot do not matter
        ("cloudfront.net", "Amazon CloudFront"),  # the suffix itself
        ("www.example.com.edgekey.net", "Akamai"),
        ("e1.dscb.akamaiedge.net", "Akamai"),
        ("example.global.ssl.fastly.net", "Fastly"),
        ("foo.azureedge.net", "Azure CDN / Front Door"),
        ("x.b-cdn.net", "Bunny CDN"),
        ("server-1.fra50.r.cloudfront.net", "Amazon CloudFront"),  # a typical reverse-DNS name
    ],
)
def test_names_of_cdns_are_recognised(name: str, expected: str) -> None:
    hint = hint_for(None, [name])
    assert hint is not None and hint.name == expected and hint.edge is True


@pytest.mark.parametrize(
    "name",
    [
        "notcloudfront.net",  # a different domain that merely ends the same way
        "cloudfront.net.evil.example",  # the suffix in the middle
        "cloudfront.network",
        "example.com",
        "",
    ],
)
def test_lookalike_names_are_not_matched(name: str) -> None:
    assert hint_for(None, [name]) is None


def test_unknown_addresses_are_unclassified_never_not_a_cdn() -> None:
    assert hint_for(None) is None
    assert hint_for(64496) is None  # a documentation AS number


def test_the_lists_are_consistent() -> None:
    assert all(hint.kind in KINDS and hint.name for hint in ASN_HINTS.values())
    assert all(isinstance(asn, int) and asn > 0 for asn in ASN_HINTS)
    for suffix, hint in NAME_HINTS:
        assert suffix == suffix.lower() and not suffix.startswith(".") and not suffix.endswith(".")
        assert hint.edge is True  # names are only listed for CDNs
    assert [suffix for suffix, _ in NAME_HINTS].count("cloudfront.net") == 1
    assert hint_for(13335).to_data() == {  # type: ignore[union-attr]
        "name": "Cloudflare",
        "kind": "cdn",
        "edge": True,
    }
