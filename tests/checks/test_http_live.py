"""DNS and HTTP checks together against real servers. Needs the network: ``pytest -m live``."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import DnsCheck
from app.checks.http import HttpCheck

pytestmark = pytest.mark.live

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
    "EGRESS_CONNECT_TIMEOUT_SEC": 10.0,
    "EGRESS_READ_TIMEOUT_SEC": 20.0,
    "USER_AGENT": "WebDueDiligence-tests/0.1",
}


def probe(host: str) -> CheckOutcome:
    http = httpx.Client()
    dns = DnsCheck().run(CheckContext("example.com", host, CONFIG, http))
    assert dns.status == "ok", dns
    return HttpCheck().run(CheckContext("example.com", host, CONFIG, http, previous={"dns": dns}))


def test_example_com_answers_over_https() -> None:
    outcome = probe("example.com")
    assert outcome.status == "ok", outcome
    data = outcome.data
    assert (data["scheme"], data["status"]) == ("https", 200)
    assert data["html_title"] == "Example Domain"
    assert data["connected_ip"] and data["headers"] and data["timing_ms"] > 0
    assert data["http_port80"]["status"] is not None  # plain HTTP answered too


def test_a_site_with_a_bad_certificate_still_yields_evidence() -> None:
    outcome = probe("expired.badssl.com")
    assert outcome.status == "ok", outcome
    assert outcome.data["https_error"] == "tls_verification_failed"
    assert outcome.data["scheme"] == "http"  # what plain HTTP said instead
