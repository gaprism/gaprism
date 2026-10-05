"""The registration check against IANA's bootstrap and real registries (``pytest -m live``)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext
from app.checks.registration import RegistrationCheck

pytestmark = pytest.mark.live

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
    "EGRESS_READ_TIMEOUT_SEC": 15.0,
    "EGRESS_CONNECT_TIMEOUT_SEC": 8.0,
}


def check(domain: str) -> Any:
    ctx = CheckContext(domain=domain, hostname=None, config=CONFIG, http=httpx.Client())
    return RegistrationCheck().run(ctx)


def test_a_gtld_domain_comes_back_with_dates_registrar_and_locks() -> None:
    outcome = check("example.com")  # IANA's own; it has existed as long as .com has
    assert outcome.status == "ok", outcome
    data = outcome.data
    assert data["registrar"]["name"] and data["created"].startswith("1995-08-14")
    assert data["days_to_expiry"] is not None and data["transfer_locked"] is True
    assert outcome.source == "rdap:rdap.verisign.com"


def test_a_swiss_domain_is_found_through_the_supplemental_server() -> None:
    outcome = check("admin.ch")  # .ch is not in IANA's bootstrap list
    assert outcome.status == "ok", outcome
    assert outcome.source == "rdap:rdap.nic.ch"
    assert outcome.data["nameservers"] and outcome.data["dates_published"] is False


def test_an_unregistered_name_and_a_tld_without_rdap_are_no_data() -> None:
    assert check("no-such-domain-0b6f1c9d.com").reason_code == "not_found"
    assert check("example.zz").reason_code == "no_rdap_service"
