"""Host-level rules, over the real checks' outputs (TLS, HTTP, DNS, IP location)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckOutcome
from app.service.geo import IpLocation
from tests.checks.test_http_check import HOST, Site, page, redirect
from tests.checks.test_http_check import run as run_http
from tests.checks.test_ip_check import FakeProvider, cloudflare, dns_outcome, german, swiss
from tests.checks.test_ip_check import run as run_ip
from tests.rules.helpers import GOOD_HEADERS, expired, fire, host, http_only, one, tls, web

HOST_RULES = [
    "TLS_INVALID",
    "TLS_EXPIRES_SOON",
    "TLS_WEAK_KEY",
    "TLS_WEAK_SIGNATURE",
    "NO_HTTPS",
    "HTTP_NO_HTTPS_REDIRECT",
    "HSTS_MISSING",
    "HSTS_WEAK",
    "CSP_MISSING",
    "XCTO_MISSING",
    "FRAME_PROTECTION_MISSING",
    "COOKIE_INSECURE",
    "SERVER_VERSION_DISCLOSED",
]


def everything(facts: Any) -> dict[str, Any]:
    """Every host rule that fires for ``facts``, by rule id."""
    return {rid: fire(rid, facts) for rid in HOST_RULES if fire(rid, facts)}


# ------------------------------------------------------------------------------ the happy path


def test_a_healthy_host_raises_nothing() -> None:
    assert everything(host(tls=tls(), http=web())) == {}


def test_a_host_whose_checks_did_not_succeed_has_nothing_to_judge() -> None:
    failed = host(
        tls=CheckOutcome("error", "timeout"),
        http=CheckOutcome("error", "timeout"),
        dns=CheckOutcome("error", "servfail"),
        ip=CheckOutcome("unavailable", "datasets_missing"),
    )
    assert everything(failed) == {}  # the failed checks are a coverage matter, not findings
    for rule_id in ("DANGLING_CNAME", "DNS_PRIVATE_ADDRESS", "LOCATION_OUTSIDE_EU_CH"):
        assert fire(rule_id, failed) == []
    assert everything(host()) == {}  # a host with no results at all


# ------------------------------------------------------------------------------ TLS


@pytest.mark.parametrize(
    ("reasons", "severity"),
    [
        (["CERTIFICATE_EXPIRED"], "high"),
        (["CERTIFICATE_NOT_YET_VALID"], "high"),
        (["UNTRUSTED_ROOT"], "high"),
        (["CERTIFICATE_VERIFY_FAILED: self signed"], "high"),
        (["HOSTNAME_MISMATCH"], "medium"),  # the certificate is fine, it is for another name
        (["HOSTNAME_MISMATCH", "CERTIFICATE_EXPIRED"], "high"),
        (["SOMETHING_NEW"], "high"),  # an unknown reason is not downgraded
    ],
)
def test_an_invalid_certificate_is_high_unless_it_is_only_for_another_name(
    reasons: list[str], severity: str
) -> None:
    outcome = tls(is_valid=False, failure_reasons=reasons, forensic=True)
    draft = one("TLS_INVALID", host(tls=outcome))
    assert (draft.severity, draft.confidence, draft.attribution) == (
        severity,
        "high",
        "hostname_supported",
    )
    assert draft.subject == f"host:{HOST}" and len(draft.evidence) == 1
    assert draft.params["host"] == HOST and draft.params["failures"]


def test_an_expired_certificate_reports_the_days_and_is_not_also_expiring_soon() -> None:
    facts = host(tls=expired())
    assert one("TLS_INVALID", facts).params["days_remaining"] == -12
    assert fire("TLS_EXPIRES_SOON", facts) == []  # expired is covered by TLS_INVALID


@pytest.mark.parametrize(
    ("days", "severity"), [(29, "low"), (8, "low"), (7, "low"), (6, "medium"), (0, "medium")]
)
def test_an_expiring_certificate_is_low_and_medium_in_the_last_week(
    days: int, severity: str
) -> None:
    draft = one("TLS_EXPIRES_SOON", host(tls=tls(days_until_expiration=days)))
    assert (draft.severity, draft.params["days"]) == (severity, days)


@pytest.mark.parametrize("days", [30, 31, 365, -1])
def test_a_certificate_with_time_left_or_already_expired_is_not_expiring_soon(days: int) -> None:
    assert fire("TLS_EXPIRES_SOON", host(tls=tls(days_until_expiration=days))) == []


def test_an_untrusted_certificate_is_judged_by_tls_invalid_only() -> None:
    outcome = tls(is_valid=False, failure_reasons=["UNTRUSTED_ROOT"], days_until_expiration=3)
    assert fire("TLS_EXPIRES_SOON", host(tls=outcome)) == []


@pytest.mark.parametrize(
    ("key_type", "bits", "weak"),
    [
        ("RSA", 1024, True),
        ("RSA", 1536, True),
        ("RSA", 2048, False),
        ("RSA", 4096, False),
        ("EC", 192, True),
        ("EC", 256, False),
        ("EC", 384, False),
        ("DSA", 2048, True),  # DSA is retired whatever its size
        ("Ed25519", None, False),
        (None, None, False),
    ],
)
def test_weak_keys(key_type: str | None, bits: int | None, weak: bool) -> None:
    outcome = tls(key_type=key_type, key_bits=bits, key_curve=None)
    drafts = fire("TLS_WEAK_KEY", host(tls=outcome))
    assert bool(drafts) is weak
    if weak:
        assert (drafts[0].severity, drafts[0].params["key_bits"]) == ("high", bits)


@pytest.mark.parametrize(
    ("digest", "weak"),
    [
        ("sha1", True),
        ("md5", True),
        ("SHA1", True),
        ("sha256", False),
        ("sha384", False),
        (None, False),
    ],
)
def test_weak_signatures(digest: str | None, weak: bool) -> None:
    outcome = tls(signature_hash=digest, signature_algorithm="sha1WithRSAEncryption")
    drafts = fire("TLS_WEAK_SIGNATURE", host(tls=outcome))
    assert bool(drafts) is weak
    if weak:
        assert drafts[0].severity == "high" and "sha1" in drafts[0].params["algorithm"]


# ------------------------------------------------------------------------------ HTTP


def test_plain_http_without_https_is_high_and_sure_when_https_is_refused() -> None:
    draft = one("NO_HTTPS", host(http=http_only()))
    assert (draft.severity, draft.confidence) == ("high", "high")
    assert draft.params["https_error"] == "refused"


def test_https_that_times_out_is_a_less_certain_finding() -> None:
    draft = one("NO_HTTPS", host(http=http_only(httpx.ReadTimeout("slow"))))
    assert (draft.severity, draft.confidence) == ("high", "medium")


def test_https_with_a_bad_certificate_is_not_called_no_https() -> None:
    import ssl

    error = httpx.ConnectError("verify failed")
    error.__cause__ = ssl.SSLCertVerificationError("expired")
    assert fire("NO_HTTPS", host(http=http_only(error))) == []  # TLS_INVALID's business


def test_a_site_on_https_is_not_no_https() -> None:
    assert fire("NO_HTTPS", host(http=web())) == []


def test_port_80_serving_content_instead_of_redirecting_is_medium() -> None:
    draft = one("HTTP_NO_HTTPS_REDIRECT", host(http=web(port80="page")))
    assert (draft.severity, draft.confidence, draft.params["status"]) == ("medium", "high", 200)


@pytest.mark.parametrize("port80", ["redirect", "refused"])
def test_a_redirect_or_a_closed_port_80_is_fine(port80: str) -> None:
    assert fire("HTTP_NO_HTTPS_REDIRECT", host(http=web(port80=port80))) == []


def test_missing_security_headers_each_raise_their_own_low_finding() -> None:
    found = everything(host(http=web([])))
    assert sorted(found) == [
        "CSP_MISSING",
        "FRAME_PROTECTION_MISSING",
        "HSTS_MISSING",
        "XCTO_MISSING",
    ]
    assert all(d.severity == "low" for ds in found.values() for d in ds)


def test_frame_ancestors_in_the_csp_counts_as_frame_protection() -> None:
    headers = [("Content-Security-Policy", "default-src 'self'; Frame-Ancestors 'self'")]
    found = everything(host(http=web(headers)))
    assert "FRAME_PROTECTION_MISSING" not in found and "CSP_MISSING" not in found


def test_a_response_that_is_not_html_needs_no_csp_xcto_or_frame_headers() -> None:
    found = everything(host(http=web([], content_type="application/json")))
    assert sorted(found) == ["HSTS_MISSING"]  # transport security applies to every response


def test_error_pages_are_not_judged_for_headers() -> None:
    assert everything(host(http=web([], status=404))) == {}


def test_the_headers_of_another_host_are_not_this_hosts_headers() -> None:
    elsewhere = "other.example.net"
    site = Site(
        {
            ("https", HOST, "/"): redirect(f"https://{elsewhere}/"),
            ("https", elsewhere, "/"): page(200, []),  # no security headers at all
            ("http", HOST, "/"): redirect(f"https://{HOST}/"),
        }
    )
    outcome = run_http(site, names={elsewhere: ["93.184.216.34"]})
    assert outcome.data["cross_host_final"] is True
    assert everything(host(http=outcome)) == {}  # the headers belong to another host


@pytest.mark.parametrize(
    ("value", "weak", "max_age"),
    [
        ("max-age=3600", True, 3600),
        ("max-age=15551999", True, 15551999),
        ("max-age=15552000", False, None),
        ("max-age=63072000; includeSubDomains; preload", False, None),
        ('max-age="300"', True, 300),
        ("includeSubDomains", True, 0),  # no max-age at all
    ],
)
def test_a_short_hsts_lifetime_is_informational(
    value: str, weak: bool, max_age: int | None
) -> None:
    headers = [h for h in GOOD_HEADERS if h[0] != "Strict-Transport-Security"]
    drafts = fire("HSTS_WEAK", host(http=web([("Strict-Transport-Security", value), *headers])))
    assert bool(drafts) is weak
    if weak:
        assert (drafts[0].severity, drafts[0].params["max_age"]) == ("informational", max_age)


def test_hsts_weak_stays_quiet_when_the_header_is_missing_altogether() -> None:
    assert fire("HSTS_WEAK", host(http=web([]))) == []  # HSTS_MISSING covers that


def test_session_cookies_without_secure_or_httponly_are_flagged_without_their_values() -> None:
    headers = [
        *GOOD_HEADERS,
        ("Set-Cookie", "sid=SECRET-1; Path=/; HttpOnly"),
        ("Set-Cookie", "PHPSESSID=SECRET-2; Path=/; Secure"),
        ("Set-Cookie", "csrftoken=SECRET-3; Secure"),  # CSRF tokens are read by scripts
        ("Set-Cookie", "theme=dark"),  # not session-like
        ("Set-Cookie", "__Host-auth=SECRET-4; Path=/; Secure; HttpOnly"),
    ]
    draft = one("COOKIE_INSECURE", host(http=web(headers)))
    assert draft.severity == "medium"
    assert draft.params["missing_secure"] == ["sid"]
    assert draft.params["missing_httponly"] == ["PHPSESSID"]
    assert draft.params["cookies"] == ["PHPSESSID", "sid"]
    assert "SECRET" not in repr(draft)  # values are never stored


def test_a_secure_prefix_implies_secure() -> None:
    headers = [*GOOD_HEADERS, ("Set-Cookie", "__Secure-session=x; Path=/; Secure; HttpOnly")]
    assert fire("COOKIE_INSECURE", host(http=web(headers))) == []


def test_ordinary_cookies_are_not_session_cookies() -> None:
    headers = [*GOOD_HEADERS, ("Set-Cookie", "lang=en"), ("Set-Cookie", "consent=1")]
    assert fire("COOKIE_INSECURE", host(http=web(headers))) == []


@pytest.mark.parametrize(
    ("server", "powered_by", "shown"),
    [
        ("nginx/1.10.3", None, "nginx/1.10.3"),
        ("Apache/2.4.58 (Ubuntu)", "PHP/8.3.1", "Apache/2.4.58 (Ubuntu), PHP/8.3.1"),
        ("nginx", None, None),
        ("cloudflare", "Express", None),
        (None, "ASP.NET 4.0", "ASP.NET 4.0"),
    ],
)
def test_versions_in_server_headers(
    server: str | None, powered_by: str | None, shown: str | None
) -> None:
    headers = list(GOOD_HEADERS)
    if server:
        headers.append(("Server", server))
    if powered_by:
        headers.append(("X-Powered-By", powered_by))
    drafts = fire("SERVER_VERSION_DISCLOSED", host(http=web(headers)))
    assert (drafts[0].params["versions"] if drafts else None) == shown
    if drafts:
        assert drafts[0].severity == "informational"


# ------------------------------------------------------------------------------ DNS


def test_a_dangling_alias_is_medium_with_low_confidence() -> None:
    dns = CheckOutcome(
        "ok", data={"dangling_cname": True, "canonical_name": "gone.example.net", "blocked": []}
    )
    draft = one("DANGLING_CNAME", host(dns=dns))
    assert (draft.severity, draft.confidence) == ("medium", "low")
    assert draft.params["target"] == "gone.example.net"
    assert (
        fire("DANGLING_CNAME", host(dns=CheckOutcome("ok", data={"dangling_cname": False}))) == []
    )


def test_private_addresses_in_public_dns() -> None:
    blocked = [{"ip": "10.0.0.5", "reason": "private"}, {"ip": "127.0.0.1", "reason": "loopback"}]
    dns = CheckOutcome("ok", data={"addresses": ["93.184.216.34"], "blocked": blocked})
    draft = one("DNS_PRIVATE_ADDRESS", host(dns=dns))
    assert draft.severity == "low"
    assert "10.0.0.5 (private)" in draft.params["addresses"]
    assert fire("DNS_PRIVATE_ADDRESS", host(dns=CheckOutcome("ok", data={"blocked": []}))) == []


# ------------------------------------------------------------------------------ location


def located(*locations: IpLocation, aliases: tuple[str, ...] = ()) -> CheckOutcome:
    table = {location.ip: location for location in locations}
    return run_ip(FakeProvider(table), dns_outcome(*table, aliases=aliases))


def test_hosts_inside_the_allowed_area_raise_nothing() -> None:
    assert fire("LOCATION_OUTSIDE_EU_CH", host(ip=located(swiss(), german()))) == []


def test_a_host_outside_the_area_is_high() -> None:
    us = IpLocation("198.51.100.7", "US", "United States", "NA", "Virginia", "Ashburn", 39.0, -77.5)
    draft = one("LOCATION_OUTSIDE_EU_CH", host(ip=located(swiss(), us)))
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "high",
        "high",
        "hostname_supported",
    )
    assert draft.params["countries"] == "US" and draft.params["edge_only"] is False
    assert "198.51.100.7 (US, Ashburn)" in draft.params["addresses"]
    assert draft.subject == f"host:{HOST}"


def test_a_cdn_edge_outside_the_area_is_medium_with_low_confidence() -> None:
    draft = one("LOCATION_OUTSIDE_EU_CH", host(ip=located(cloudflare())))
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "medium",
        "low",
        "shared_infrastructure",
    )
    assert draft.params["edge_only"] is True and "Cloudflare" in draft.params["addresses"][0]


def test_one_address_in_the_area_and_a_cdn_edge_outside_is_still_only_an_edge() -> None:
    draft = one("LOCATION_OUTSIDE_EU_CH", host(ip=located(swiss(), cloudflare())))
    assert (draft.severity, draft.confidence) == ("medium", "low")


def test_a_cloud_provider_address_registered_abroad_is_high_but_less_certain() -> None:
    aws = IpLocation(
        "52.1.1.1", "US", "United States", "NA", "Virginia", "Ashburn", 39, -77, 16509, "Amazon"
    )
    draft = one("LOCATION_OUTSIDE_EU_CH", host(ip=located(aws)))
    assert (draft.severity, draft.confidence) == ("high", "medium")  # cloud IPs geolocate to HQ
    assert draft.params["addresses"][0].endswith("Amazon Web Services)")


def test_a_real_address_outside_next_to_an_edge_is_high() -> None:
    us = IpLocation("198.51.100.7", "US", "United States", "NA", None, None, None, None, None, None)
    draft = one("LOCATION_OUTSIDE_EU_CH", host(ip=located(us, cloudflare())))
    assert (draft.severity, draft.params["countries"]) == ("high", "CA, US")


def test_the_allowed_area_is_configurable() -> None:
    us = IpLocation("198.51.100.7", "US", "United States", "NA", None, None, None, None, None, None)
    facts = host(ip=located(us))
    assert fire("LOCATION_OUTSIDE_EU_CH", facts)
    assert fire("LOCATION_OUTSIDE_EU_CH", facts, allowed_countries=frozenset({"CH", "US"})) == []


def test_an_address_without_a_country_is_not_outside() -> None:
    nowhere = IpLocation(
        "198.51.100.9", None, None, None, None, None, None, None, 64500, "Somebody"
    )
    assert fire("LOCATION_OUTSIDE_EU_CH", host(ip=located(nowhere))) == []
