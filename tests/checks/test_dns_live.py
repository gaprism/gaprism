"""The DNS check against real resolvers. Needs the network: run with ``pytest -m live``."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext
from app.checks.dns import DnsCheck

pytestmark = pytest.mark.live

PUBLIC: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
}


def check(host: str, config: dict[str, Any] = PUBLIC) -> Any:
    ctx = CheckContext(domain="example.com", hostname=host, config=config, http=httpx.Client())
    return DnsCheck().run(ctx)


def test_example_com_resolves_through_the_public_resolvers() -> None:
    outcome = check("example.com")
    assert outcome.status == "ok", outcome
    assert outcome.data["addresses"] and outcome.data["ns"]
    assert outcome.data["blocked"] == [] and outcome.data["errors"] == {}


def test_a_name_that_does_not_exist_is_no_data() -> None:
    # `.invalid` never exists (RFC 2606). Not a name below example.com: that zone answers
    # "no such type" (NODATA) for every name through a wildcard.
    outcome = check("no-such-host-0b6f1c.invalid")
    assert (outcome.status, outcome.reason_code) == ("no_data", "nxdomain")


def test_a_wildcard_zone_answers_nodata_which_is_not_nxdomain() -> None:
    outcome = check("no-such-host-0b6f1c.example.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_records")


def test_a_cname_chain_is_followed_for_real() -> None:
    outcome = check("www.iana.org")  # an alias at the time of writing; the chain may change
    assert outcome.status == "ok", outcome
    assert outcome.data["addresses"]
