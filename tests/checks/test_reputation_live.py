"""The reputation check against the real security resolvers. Needs the network: ``pytest -m live``.

Two names that exist to be blocked: ``examplemalwaredomain.com`` (a test name for malware blocking,
which Quad9 refuses) and ``malware.testcategory.com`` (Cloudflare's test name for the category,
which 1.1.1.2 answers with 0.0.0.0). They notice when a resolver changes the way it says "blocked",
and confirm what the recorded answers of ``test_reputation_check`` were taken from.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import DnsCheck
from app.checks.reputation import ReputationCheck, ResolverHealth

pytestmark = pytest.mark.live

CONFIG = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "REPUTATION_RESOLVERS": ["quad9", "cloudflare"],
    "DNS_TIMEOUT_SECONDS": 5.0,
}


def reputation_of(host: str) -> CheckOutcome:
    previous: dict[str, CheckOutcome] = {}

    def context() -> CheckContext:
        return CheckContext(
            domain=host, hostname=host, config=CONFIG, http=httpx.Client(), previous=dict(previous)
        )

    previous["dns"] = DnsCheck().run(context())
    assert previous["dns"].status == "ok", previous["dns"].reason_code
    return ReputationCheck(health=ResolverHealth()).run(context())


def rows_of(outcome: CheckOutcome) -> dict[str, dict[str, Any]]:
    return {row["key"]: row for row in outcome.data["resolvers"]}


def test_quad9_refuses_a_name_that_exists_to_be_blocked() -> None:
    outcome = reputation_of("examplemalwaredomain.com")
    assert outcome.status == "ok" and "Quad9" in outcome.data["blocked_by"]
    quad9 = rows_of(outcome)["quad9"]
    assert (quad9["verdict"], quad9["how"], quad9["rcode"]) == ("blocked", "nxdomain", "NXDOMAIN")
    assert 17 in quad9["ede"]  # Filtered: the resolver says it did so on purpose


def test_cloudflares_malware_resolver_answers_a_blocked_name_with_nothing() -> None:
    outcome = reputation_of("malware.testcategory.com")
    assert outcome.status == "ok" and "Cloudflare (1.1.1.2)" in outcome.data["blocked_by"]
    cloudflare = rows_of(outcome)["cloudflare"]
    assert (cloudflare["verdict"], cloudflare["how"]) == ("blocked", "unspecified_address")
    assert cloudflare["answers"] == ["0.0.0.0"] and 16 in cloudflare["ede"]  # Censored
    assert rows_of(outcome)["quad9"]["verdict"] == "clear"  # the other one does not block it


def test_an_ordinary_name_is_not_blocked_by_either() -> None:
    outcome = reputation_of("example.com")
    assert outcome.status == "ok" and outcome.data["blocked_by"] == []
    assert [row["verdict"] for row in outcome.data["resolvers"]] == ["clear", "clear"]
    assert outcome.data["decided"] == 2
