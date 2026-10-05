"""Builders for rule tests: facts from the real checks' outputs, so the rules are tested against
what the checks really produce."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.checks.base import CheckOutcome
from app.checks.tls import outcome_from_probe
from app.config import DEFAULT_DATA_LOCATION_ALLOWED
from app.rules import RULES, DomainFacts, Draft, HostFacts, IpFacts, Result, RuleSettings
from tests.checks.test_http_check import HOST, Site, page, redirect, refused
from tests.checks.test_http_check import run as run_http
from tests.checks.test_tls_check import probe_result

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
DOMAIN = "example.com"
ALLOWED = frozenset(DEFAULT_DATA_LOCATION_ALLOWED)


def settings(**overrides: Any) -> RuleSettings:
    values: dict[str, Any] = {
        "domain": DOMAIN,
        "now": NOW,
        "allowed_countries": ALLOWED,
        "breach_recent_months": 24,
    }
    values.update(overrides)
    return RuleSettings(**values)


def result(outcome: CheckOutcome) -> Result:
    return Result(str(uuid.uuid4()), outcome.status, outcome.reason_code, outcome.data)


def host(hostname: str = HOST, **outcomes: CheckOutcome) -> HostFacts:
    return HostFacts(
        id=str(uuid.uuid4()),
        hostname=hostname,
        source="ct",
        results={key: result(outcome) for key, outcome in outcomes.items()},
    )


def domain_facts(domain: str = DOMAIN, **outcomes: CheckOutcome) -> DomainFacts:
    return DomainFacts(domain, {key: result(outcome) for key, outcome in outcomes.items()})


def fire(rule_id: str, facts: HostFacts | DomainFacts | IpFacts, **overrides: Any) -> list[Draft]:
    """What a rule decides about ``facts``."""
    return list(RULES[rule_id].evaluate(facts, settings(**overrides)))


def one(rule_id: str, facts: HostFacts | DomainFacts | IpFacts, **overrides: Any) -> Draft:
    drafts = fire(rule_id, facts, **overrides)
    assert len(drafts) == 1, f"{rule_id}: expected one finding, got {drafts}"
    return drafts[0]


# ------------------------------------------------------------------------------ TLS


def tls(**fields: Any) -> CheckOutcome:
    """A healthy certificate unless the fields say otherwise."""
    return outcome_from_probe(probe_result(**fields))


def expired(**fields: Any) -> CheckOutcome:
    values: dict[str, Any] = {
        "is_valid": False,
        "time_valid": False,
        "failure_reasons": ["CERTIFICATE_EXPIRED"],
        "forensic": True,
        "days_until_expiration": -12,
    }
    values.update(fields)
    return tls(**values)


# ------------------------------------------------------------------------------ HTTP

GOOD_HEADERS = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
]


def web(
    headers: list[tuple[str, str]] | None = None,
    *,
    status: int = 200,
    content_type: str = "text/html; charset=utf-8",
    port80: Any = "redirect",
    https: Any = None,
) -> CheckOutcome:
    """The real HTTP check over a scripted site: HTTPS answers with ``headers``.

    Port 80 either redirects to HTTPS (``"redirect"``), serves a page (``"page"``) or is refused.
    """
    main = https
    if main is None:
        main = page(status, headers if headers is not None else GOOD_HEADERS)
        main.headers["content-type"] = content_type
    routes: dict[tuple[str, str, str], Any] = {("https", HOST, "/"): main}
    if port80 == "redirect":
        routes[("http", HOST, "/")] = redirect(f"https://{HOST}/")
    elif port80 == "page":
        routes[("http", HOST, "/")] = page(200)
    else:
        routes[("http", HOST, "/")] = refused()
    return run_http(Site(routes))


def http_only(https_error: Any = None) -> CheckOutcome:
    """HTTPS fails with ``https_error`` while plain HTTP serves a page."""
    routes: dict[tuple[str, str, str], Any] = {
        ("https", HOST, "/"): https_error or refused(),
        ("http", HOST, "/"): page(200),
    }
    return run_http(Site(routes))
