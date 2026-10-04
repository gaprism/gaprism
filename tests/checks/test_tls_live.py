"""The DNS and TLS checks together against real servers. Needs the network: ``pytest -m live``.

The broken-certificate cases use badssl.com, a public site that exists to be probed.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import DnsCheck
from app.checks.tls import TlsCheck

pytestmark = pytest.mark.live

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
    "EGRESS_CONNECT_TIMEOUT_SEC": 10.0,
}


def probe(host: str) -> CheckOutcome:
    http = httpx.Client()
    dns = DnsCheck().run(CheckContext("example.com", host, CONFIG, http))
    assert dns.status == "ok", dns
    return TlsCheck().run(CheckContext("example.com", host, CONFIG, http, previous={"dns": dns}))


def test_a_healthy_site_is_verified_with_full_facts() -> None:
    outcome = probe("example.com")
    assert outcome.status == "ok", outcome
    data = outcome.data
    assert data["verified"] is True and data["failures"] == [] and data["forensic"] is False
    assert data["protocol"] in {"TLSv1.2", "TLSv1.3"}
    certificate = data["certificate"]
    assert certificate["key_type"] in {"RSA", "EC"} and certificate["key_bits"]
    assert certificate["days_remaining"] > 0 and certificate["sans"]
    assert data["ip"]


@pytest.mark.parametrize(
    ("host", "failure"),
    [
        ("expired.badssl.com", "expired"),
        ("wrong.host.badssl.com", "hostname_mismatch"),
        ("self-signed.badssl.com", "untrusted"),
    ],
)
def test_broken_certificates_are_collected_and_labelled(host: str, failure: str) -> None:
    outcome = probe(host)
    assert outcome.status == "ok", outcome
    assert outcome.data["verified"] is False and outcome.data["forensic"] is True
    assert failure in outcome.data["failures"]
    assert outcome.data["certificate"]["fingerprint_sha256"]
