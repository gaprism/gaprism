"""The security.txt check over recorded real files (GitHub, Google, admin.ch) and a mock web."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.fetch import MAX_DOCUMENT_BYTES
from app.checks.securitytxt import (
    BUDGET_SECONDS,
    MAX_VALUES,
    SecurityTxtCheck,
    analyse,
    parse_expires,
    parse_security_txt,
)
from runner.egress import EgressHTTPClient

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "domain"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
GITHUB = (FIXTURES / "security_github.txt").read_text(encoding="utf-8")
GOOGLE = (FIXTURES / "security_google.txt").read_text(encoding="utf-8")
ADMIN = (FIXTURES / "security_admin_ch.txt").read_text(encoding="utf-8")
WELL_KNOWN = "/.well-known/security.txt"
# GitHub regenerates its Expires line on every request (a rolling window), so tests read the
# recorded value instead of hard-coding it.
EXPIRES_RAW = next(
    line.split(": ", 1)[1] for line in GITHUB.splitlines() if line.startswith("Expires:")
)
EXPIRES = datetime.fromisoformat(EXPIRES_RAW.upper())


def text(body: str, content_type: str = "text/plain; charset=utf-8") -> httpx.Response:
    return httpx.Response(200, content=body.encode(), headers={"content-type": content_type})


def redirect(location: str, status: int = 301) -> httpx.Response:
    return httpx.Response(status, headers={"location": location}, content=b"moved")


class Web:
    """A mock web keyed by (host, path); anything unlisted is a 404. Remembers the requests."""

    def __init__(self, pages: dict[tuple[str, str], Any] | None = None) -> None:
        self.pages = pages or {}
        self.requests: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        key = (request.headers["host"], request.url.path)
        self.requests.append(key)
        page = self.pages.get(key)
        if isinstance(page, Exception):
            raise page
        if page is None:
            return httpx.Response(404, text="Not found", headers={"content-type": "text/html"})
        return page


def run(
    web: Callable[[httpx.Request], httpx.Response],
    domain: str = "example.com",
    *,
    ip: str = "93.184.216.34",
    monotonic: Callable[[], float] | None = None,
) -> CheckOutcome:
    def factory(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            custom_transport=httpx.MockTransport(web),
            resolver_fn=lambda name: [ip],
            max_response_bytes=MAX_DOCUMENT_BYTES,
            truncate_body=True,
        )

    kwargs: dict[str, Any] = {"monotonic": monotonic} if monotonic else {}
    check = SecurityTxtCheck(
        client_factory=factory, name_resolver=lambda config, name: [ip], clock=lambda: NOW, **kwargs
    )
    ctx = CheckContext(domain=domain, hostname=None, config={}, http=httpx.Client())
    return check.run(ctx)


# ------------------------------------------------------------------------------ parsing


def test_real_files_are_read_field_by_field() -> None:
    github = parse_security_txt(GITHUB)["fields"]
    assert github["contact"] == ["https://hackerone.com/github"]
    assert github["expires"] == [EXPIRES_RAW] and EXPIRES_RAW.endswith("z")  # a real lower-case z
    assert github["canonical"] == ["https://github.com/.well-known/security.txt"]
    assert github["preferred-languages"] == ["en"] and github["hiring"] == [
        "https://github.careers"
    ]

    google = parse_security_txt(GOOGLE)["fields"]
    assert google["contact"] == ["https://g.co/vulnz", "mailto:security@google.com"]
    assert google["encryption"] == ["https://services.google.com/corporate/publickey.txt"]

    admin = parse_security_txt(ADMIN)  # starts with comments
    assert admin["fields"]["contact"] and admin["fields"]["expires"] and not admin["signed"]


def test_comments_unknown_fields_and_noise_are_ignored() -> None:
    parsed = parse_security_txt(
        "# a comment\n\nContact: mailto:a@example.com\nX-Custom: whatever\nnot a field\n"
        "contact : https://example.com/report\nExpires: 2027-01-01T00:00:00Z\n"
    )
    assert parsed["fields"] == {
        "contact": ["mailto:a@example.com", "https://example.com/report"],
        "expires": ["2027-01-01T00:00:00Z"],
    }


def test_a_pgp_signed_file_is_unwrapped_and_flagged_as_signed() -> None:
    signed = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
        "-----BEGIN PGP SIGNATURE-----\n\niQEzBAEBCgAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n"
    )
    parsed = parse_security_txt(signed)
    assert parsed["signed"] is True
    assert parsed["fields"] == {
        "contact": ["mailto:security@example.com"],
        "expires": ["2027-01-01T00:00:00Z"],
    }  # neither the armor headers nor the signature are read as fields


def test_values_are_bounded_and_cleaned() -> None:
    many = "\n".join(f"Contact: https://example.com/{n}" for n in range(50))
    assert len(parse_security_txt(many)["fields"]["contact"]) == MAX_VALUES
    long = parse_security_txt("Contact: " + "x" * 5000 + "\x00\x1b[31m")["fields"]["contact"][0]
    assert len(long) <= 300 and "\x00" not in long and "\x1b" not in long
    assert parse_security_txt("Contact: x\n" * 5000)["fields"]["contact"] == ["x"] * MAX_VALUES


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-11-04T07:17:01z", datetime(2026, 11, 4, 7, 17, 1, tzinfo=UTC)),
        ("2026-11-04T07:17:01Z", datetime(2026, 11, 4, 7, 17, 1, tzinfo=UTC)),
        ("2026-11-04t07:17:01z", datetime(2026, 11, 4, 7, 17, 1, tzinfo=UTC)),
        ("2026-11-04T08:17:01+01:00", datetime(2026, 11, 4, 7, 17, 1, tzinfo=UTC)),
        ("2026-11-04T07:17:01", datetime(2026, 11, 4, 7, 17, 1, tzinfo=UTC)),  # no zone: UTC
        ("2026-11-04", datetime(2026, 11, 4, tzinfo=UTC)),
        ("next year", None),
        ("", None),
        ("2026-13-45T00:00:00Z", None),
    ],
)
def test_expiry_dates_in_the_forms_seen_in_the_wild(value: str, expected: datetime | None) -> None:
    parsed = parse_expires(value)
    assert (parsed.astimezone(UTC) if parsed else None) == expected


# ------------------------------------------------------------------------------ analysis


def facts(
    fields: dict[str, list[str]],
    *,
    url: str = "https://example.com/.well-known/security.txt",
    content_type: str = "text/plain",
    domain: str = "example.com",
) -> dict[str, Any]:
    parsed = {"signed": False, "fields": fields}
    return analyse(parsed, url=url, domain=domain, content_type=content_type, now=NOW)


GOOD = {"contact": ["mailto:s@example.com"], "expires": ["2027-01-01T00:00:00Z"]}


def test_a_good_file_has_no_problems_and_a_countdown() -> None:
    result = facts(GOOD)
    assert result["problems"] == [] and result["signed"] is False
    assert result["expires"] == "2027-01-01T00:00:00+00:00"
    assert result["days_to_expiry"] == (datetime(2027, 1, 1, tzinfo=UTC) - NOW).days


@pytest.mark.parametrize(
    ("fields", "kwargs", "problems"),
    [
        ({"expires": GOOD["expires"]}, {}, ["missing_contact"]),
        ({"contact": GOOD["contact"]}, {}, ["missing_expires"]),
        (
            {**GOOD, "expires": ["2027-01-01T00:00:00Z", "2028-01-01T00:00:00Z"]},
            {},
            ["multiple_expires"],
        ),
        ({**GOOD, "expires": ["someday"]}, {}, ["invalid_expires"]),
        ({**GOOD, "expires": ["2026-10-04T00:00:00Z"]}, {}, ["expired"]),
        (GOOD, {"content_type": "text/html"}, ["not_plain_text"]),
        (GOOD, {"content_type": ""}, ["not_plain_text"]),
        (GOOD, {"url": "http://example.com/.well-known/security.txt"}, ["not_https"]),
        (GOOD, {"url": "https://other.example.net/.well-known/security.txt"}, ["offsite"]),
        (GOOD, {"url": "https://www.example.com/.well-known/security.txt"}, []),
        (
            {**GOOD, "canonical": ["https://example.com/security.txt"]},
            {},
            ["canonical_mismatch"],
        ),
        ({**GOOD, "canonical": ["https://example.com/.well-known/security.txt"]}, {}, []),
        ({}, {}, ["missing_contact", "missing_expires"]),
    ],
)
def test_what_is_wrong_with_a_file(
    fields: dict[str, list[str]], kwargs: dict[str, Any], problems: list[str]
) -> None:
    assert facts(fields, **kwargs)["problems"] == problems


def test_a_lookalike_domain_is_offsite() -> None:
    result = facts(GOOD, url="https://evilexample.com/.well-known/security.txt")
    assert result["problems"] == ["offsite"]


# ------------------------------------------------------------------------------ the check


def test_a_file_at_the_well_known_location_is_found() -> None:
    web = Web({("github.com", WELL_KNOWN): text(GITHUB)})
    outcome = run(web, "github.com")

    assert (outcome.status, outcome.source) == ("ok", "https")
    data = outcome.data
    assert data["url"] == "https://github.com/.well-known/security.txt" and data["hops"] == []
    assert data["fields"]["contact"] == ["https://hackerone.com/github"]
    assert data["expires"] == EXPIRES.isoformat() and data["days_to_expiry"] == (EXPIRES - NOW).days
    assert data["problems"] == []  # the lower-case z, the canonical URL: all in order
    assert data["tried"] == [
        {"url": f"https://github.com{WELL_KNOWN}", "status": 200, "error": None}
    ]
    assert web.requests == [("github.com", WELL_KNOWN)]  # found: nothing else was asked


def test_a_redirect_from_the_bare_domain_to_www_is_followed_and_reported() -> None:
    web = Web(
        {
            ("google.com", WELL_KNOWN): redirect("https://www.google.com/.well-known/security.txt"),
            ("www.google.com", WELL_KNOWN): text(GOOGLE, "text/plain"),
        }
    )
    outcome = run(web, "google.com")
    data = outcome.data
    assert (
        outcome.status == "ok" and data["url"] == "https://www.google.com/.well-known/security.txt"
    )
    assert data["hops"] == ["https://google.com/.well-known/security.txt"]
    assert data["requested"] == "https://google.com/.well-known/security.txt"
    assert data["problems"] == []  # www.google.com is the same domain


def test_the_root_location_is_the_fallback() -> None:
    web = Web({("example.com", "/security.txt"): text(GITHUB.replace("github.com", "example.com"))})
    outcome = run(web)
    assert outcome.status == "ok" and outcome.data["url"] == "https://example.com/security.txt"
    assert [r[1] for r in web.requests] == [WELL_KNOWN, "/security.txt"]


def test_no_file_anywhere_is_no_data_and_the_domain_is_not_chased_to_www() -> None:
    web = Web()
    outcome = run(web)
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_security_txt")
    assert [t["status"] for t in outcome.data["tried"]] == [404, 404]
    assert {host for host, _ in web.requests} == {"example.com"}  # its own server answered


def test_a_page_that_is_not_a_security_txt_does_not_count_even_with_status_200() -> None:
    soft404 = text("<!doctype html><html><body>Contact: us</body></html>", "text/html")
    web = Web(
        {("example.com", WELL_KNOWN): soft404, ("example.com", "/security.txt"): text("hello")}
    )
    outcome = run(web)
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_security_txt")
    assert [t["error"] for t in outcome.data["tried"]] == ["not_security_txt", "not_security_txt"]


def test_a_domain_without_a_web_server_falls_back_to_www() -> None:
    refused = httpx.ConnectError("refused")
    web = Web(
        {
            ("example.com", WELL_KNOWN): refused,
            ("example.com", "/security.txt"): refused,
            ("www.example.com", WELL_KNOWN): text(GITHUB),
        }
    )
    outcome = run(web)
    assert outcome.status == "ok" and outcome.data["url"].startswith("https://www.example.com/")
    assert [t["error"] for t in outcome.data["tried"][:2]] == ["connection_failed"] * 2


def test_when_nothing_could_be_asked_it_is_an_error_not_an_absence() -> None:
    timeout = httpx.ReadTimeout("slow")
    web = Web(
        {
            (host, path): timeout
            for host in ("example.com", "www.example.com")
            for path in (WELL_KNOWN, "/security.txt")
        }
    )
    outcome = run(web)
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")
    assert len(outcome.data["tried"]) == 4


def test_an_unreachable_apex_and_a_www_without_the_file_is_still_an_error() -> None:
    web = Web(
        {
            ("example.com", WELL_KNOWN): httpx.ConnectError("x"),
            ("example.com", "/security.txt"): httpx.ConnectError("x"),
        }
    )
    outcome = run(web)  # www answers 404: that says nothing about the domain itself
    assert (outcome.status, outcome.reason_code) == ("error", "connection_failed")


def test_a_redirect_loop_is_not_a_file() -> None:
    web = Web(
        {
            ("example.com", WELL_KNOWN): redirect("https://example.com/a"),
            ("example.com", "/a"): redirect("https://example.com/b"),
            ("example.com", "/b"): redirect("https://example.com/c"),
            ("example.com", "/c"): redirect("https://example.com/d"),
            ("example.com", "/d"): text(GITHUB),
        }
    )
    outcome = run(web)
    assert outcome.status == "no_data"  # three hops are allowed, the fourth file is never fetched
    assert ("example.com", "/d") not in web.requests


def test_redirects_off_the_domain_and_down_to_http_are_flagged() -> None:
    elsewhere = Web(
        {
            ("example.com", WELL_KNOWN): redirect(
                "https://security.example.net/.well-known/security.txt"
            ),
            ("security.example.net", WELL_KNOWN): text(GITHUB.replace("github.com", "example.net")),
        }
    )
    assert "offsite" in run(elsewhere).data["problems"]

    plain = Web(
        {
            ("example.com", WELL_KNOWN): redirect("http://example.com/plain/security.txt"),
            ("example.com", "/plain/security.txt"): text(GITHUB),
        }
    )
    assert "not_https" in run(plain).data["problems"]


def test_an_expired_file_is_found_and_says_so() -> None:
    old = GITHUB.replace(EXPIRES_RAW, "2026-09-01T00:00:00Z")
    outcome = run(Web({("example.com", WELL_KNOWN): text(old)}))
    assert outcome.status == "ok"
    assert "expired" in outcome.data["problems"] and outcome.data["days_to_expiry"] < 0


def test_an_oversized_file_is_cut_and_flagged() -> None:
    big = GITHUB + "\n# " + "x" * 100_000
    outcome = run(Web({("example.com", WELL_KNOWN): text(big)}))
    assert outcome.status == "ok" and outcome.data["truncated"] is True


def test_a_private_address_is_never_contacted() -> None:
    web = Web({("example.com", WELL_KNOWN): text(GITHUB)})
    outcome = run(web, ip="192.168.1.10")
    assert (outcome.status, outcome.reason_code) == ("error", "blocked_destination")
    assert web.requests == []


def test_the_time_budget_stops_the_attempts() -> None:
    ticks = iter([0.0, 0.0, BUDGET_SECONDS + 1, *([BUDGET_SECONDS + 1] * 20)])
    web = Web()
    outcome = run(web, monotonic=lambda: next(ticks))
    assert len(web.requests) == 1  # one attempt, then the budget was gone
    assert any(t.get("error") == "budget_exceeded" for t in outcome.data["tried"])


def test_everything_is_storable_as_json() -> None:
    import json

    outcome = run(Web({("example.com", WELL_KNOWN): text(GITHUB)}))
    json.dumps(outcome.data)
