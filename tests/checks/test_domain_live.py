"""The security.txt, HSTS preload, breach and name-server checks for real (``pytest -m live``)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext
from app.checks.breaches import BreachesCheck
from app.checks.domain_dns import DomainDnsCheck
from app.checks.hsts_preload import HstsPreloadCheck
from app.checks.securitytxt import SecurityTxtCheck

pytestmark = pytest.mark.live

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
    "EGRESS_READ_TIMEOUT_SEC": 15.0,
    "EGRESS_CONNECT_TIMEOUT_SEC": 8.0,
}
HTTP = httpx.Client(timeout=20, headers={"User-Agent": "WebDueDiligence-tests/0.1"})


def run(check: Any, domain: str) -> Any:
    return check.run(CheckContext(domain=domain, hostname=None, config=CONFIG, http=HTTP))


def test_github_has_a_security_txt_with_a_contact_and_is_on_the_preload_list() -> None:
    security = run(SecurityTxtCheck(), "github.com")
    assert security.status == "ok", security
    assert security.data["fields"]["contact"] and "expired" not in security.data["problems"]
    hsts = run(HstsPreloadCheck(), "github.com")
    assert hsts.status == "ok" and hsts.data["status"] == "preloaded"


def test_a_redirect_to_www_is_followed_for_security_txt() -> None:
    outcome = run(SecurityTxtCheck(), "google.com")  # google.com redirects to www.google.com
    assert outcome.status == "ok", outcome
    assert outcome.data["hops"] and outcome.data["url"].startswith("https://www.google.com/")


def test_a_domain_without_security_txt_is_no_data() -> None:
    outcome = run(SecurityTxtCheck(), "example.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_security_txt")


def test_adobe_has_a_documented_breach_and_example_com_has_none() -> None:
    adobe = run(BreachesCheck(), "adobe.com")
    assert adobe.status == "ok" and adobe.data["latest_breach_date"] == "2013-10-04"
    none = run(BreachesCheck(), "example.com")
    assert (none.status, none.reason_code) == ("no_data", "no_breach_known")


def test_github_has_spread_out_name_servers_and_caa() -> None:
    outcome = run(DomainDnsCheck(), "github.com")
    assert outcome.status == "ok", outcome
    ns = outcome.data["ns"]
    assert ns["count"] >= 4 and len(ns["operators"]) >= 2 and ns["problems"] == []
    assert outcome.data["caa"]["found"] is True and outcome.data["caa"]["issuers"]
