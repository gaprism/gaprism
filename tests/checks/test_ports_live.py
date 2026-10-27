"""The ports providers against the real, keyless Shodan InternetDB. Run with ``pytest -m live``.

The Shodan host API is deliberately not called here: it needs the owner's key, which is only used
with their say-so.
"""

from __future__ import annotations

import httpx
import pytest

from app.checks.base import CheckContext
from app.checks.dns import DnsCheck
from app.checks.ports import PortsCheck
from app.service.ports import InternetDbProvider
from app.service.ratelimit import RateLimiter

pytestmark = pytest.mark.live

CONFIG = {
    "PORTS_PROVIDER": "internetdb",
    "INTERNETDB_RATE_PER_SECOND": 1.0,
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
}


def client() -> httpx.Client:
    return httpx.Client(timeout=20.0, headers={"User-Agent": "Gaprism-tests/0.1"})


def test_an_address_internetdb_has_never_seen_is_no_data() -> None:
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): never routed, so never scanned.
    with client() as http:
        result = InternetDbProvider(http, RateLimiter(1.0)).lookup("192.0.2.1")
    assert (result.status, result.reason) == ("no_data", "no_information"), result


def test_the_whole_chain_dns_then_ports_works_for_a_real_host() -> None:
    with client() as http:
        dns_ctx = CheckContext(domain="badssl.com", hostname="badssl.com", config=CONFIG, http=http)
        dns = DnsCheck().run(dns_ctx)
        assert dns.status == "ok" and dns.data["addresses"], dns

        ports_ctx = CheckContext(
            domain="badssl.com",
            hostname="badssl.com",
            config=CONFIG,
            http=http,
            previous={"dns": dns},
        )
        outcome = PortsCheck().run(ports_ctx)

    assert outcome.status in ("ok", "no_data"), outcome  # the scanner may not know the address
    assert outcome.source == "internetdb" and outcome.data["provider"] == "internetdb"
    for entry in outcome.data["addresses"]:
        assert entry["status"] in ("ok", "no_data")
        if entry["status"] == "ok":
            assert entry["facts"]["ports"], entry
            assert entry["attribution"] in (
                "ip_only",
                "hostname_supported",
                "shared_infrastructure",
            )
