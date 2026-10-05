"""The email check against real DNS and real MTA-STS policies. Run with ``pytest -m live``."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext
from app.checks.email import EmailCheck

pytestmark = pytest.mark.live

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
    "EGRESS_READ_TIMEOUT_SEC": 15.0,
    "EGRESS_CONNECT_TIMEOUT_SEC": 8.0,
}


def check(domain: str) -> Any:
    ctx = CheckContext(domain=domain, hostname=None, config=CONFIG, http=httpx.Client())
    return EmailCheck().run(ctx)


def test_google_com_has_spf_dmarc_and_an_enforced_mta_sts_policy() -> None:
    outcome = check("google.com")  # well maintained; the details may change, the shape does not
    assert outcome.status == "ok", outcome
    data = outcome.data
    assert data["spf"]["found"] is True and data["spf"]["qualifier"] in ("fail", "softfail")
    assert data["dmarc"]["found"] is True and data["dmarc"]["policy"] in ("quarantine", "reject")
    assert data["mx"]["providers"] == ["Google Workspace"]
    assert data["mta_sts"]["found"] is True and data["mta_sts"]["policy"]["fetched"] is True
    assert data["errors"] == {}


def test_example_com_publishes_null_mx_and_revokes_dkim() -> None:
    outcome = check("example.com")  # IANA keeps it as a model of a domain that sends no mail
    assert outcome.status == "ok", outcome
    assert outcome.data["mx"]["null_mx"] is True
    assert outcome.data["spf"]["found"] is True and outcome.data["dkim"]["found"] == []


def test_a_name_that_does_not_exist_is_no_data() -> None:
    outcome = check("no-such-domain-0b6f1c.invalid")
    assert (outcome.status, outcome.reason_code) == ("no_data", "nxdomain")
