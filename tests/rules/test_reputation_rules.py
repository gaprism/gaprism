"""HOST_BLOCKED_BY_SECURITY_DNS, over what the real reputation check makes of scripted answers."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.rcode
import pytest

from app.checks.base import CheckOutcome
from app.rules import RULES
from app.service.findings import render_value
from tests.checks.test_reputation_check import (
    CLOUDFLARE_BLOCKED,
    CLOUDFLARE_CLEAR,
    CLOUDFLARE_DNSSEC_BOGUS,
    HOST,
    QUAD9_BLOCKED,
    QUAD9_CLEAR,
    QUAD9_DNSSEC_BOGUS,
    Network,
    both,
    dns_result,
    reply,
    wire,
)
from tests.checks.test_reputation_check import run as run_reputation
from tests.rules.helpers import fire, host, one

RULE = "HOST_BLOCKED_BY_SECURITY_DNS"


def judged(network: Network, **options: Any) -> Any:
    """The host as the stored results of a scan would show it."""
    dns = dns_result()
    return host(HOST, dns=dns, reputation=run_reputation(network, dns=dns, **options))


def test_a_host_blocked_by_both_resolvers_is_high_with_medium_confidence() -> None:
    subject = judged(both(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_BLOCKED)))
    draft = one(RULE, subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "high",
        "medium",
        "hostname_supported",
    )
    assert draft.subject == f"host:{HOST}" and draft.host_id == subject.id
    assert draft.params["blocked_by"] == ["Quad9", "Cloudflare (1.1.1.2)"]
    assert draft.params["block_how"] == ["nxdomain", "unspecified_address"]
    assert draft.params["asked"] == 2
    assert draft.evidence == (subject.results["reputation"].id, subject.results["dns"].id)


def test_one_resolver_blocking_is_medium() -> None:
    draft = one(RULE, judged(both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_BLOCKED))))
    assert (draft.severity, draft.confidence) == ("medium", "medium")
    assert draft.params["blocked_by"] == ["Cloudflare (1.1.1.2)"]
    assert draft.params["block_how"] == ["unspecified_address"]


def test_a_resolver_that_blocks_without_changing_the_answer_still_counts() -> None:
    blocked = reply(answers=("93.184.216.34",), ede=(15,))  # it resolved, yet it says blocked
    draft = one(RULE, judged(both(blocked, wire(CLOUDFLARE_CLEAR))))
    assert draft.params["block_how"] == ["ede"]


@pytest.mark.parametrize(
    "network",
    [
        both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR)),  # nobody blocks it
        both(wire(QUAD9_DNSSEC_BOGUS), wire(CLOUDFLARE_DNSSEC_BOGUS)),  # failures are not blocks
        both(reply(dns.rcode.NXDOMAIN), wire(CLOUDFLARE_CLEAR)),  # "no such name", no reason given
        both(dns.exception.Timeout(), wire(CLOUDFLARE_CLEAR)),  # one did not answer
    ],
)
def test_a_name_that_is_not_blocked_gives_no_finding(network: Network) -> None:
    assert fire(RULE, judged(network)) == []


def test_an_answer_that_is_not_a_block_never_counts_when_the_other_resolver_is_silent() -> None:
    timeouts = both(wire(QUAD9_DNSSEC_BOGUS), dns.exception.Timeout())
    assert fire(RULE, judged(timeouts)) == []


@pytest.mark.parametrize(
    "outcome",
    [
        None,
        CheckOutcome("error", "timeout"),
        CheckOutcome("skipped", "disabled"),
        CheckOutcome("skipped", "no_address_record"),
        CheckOutcome("no_data", "no_verdict", {"resolvers": [], "blocked_by": []}),
    ],
)
def test_without_a_result_of_the_check_that_answered_the_rule_stays_silent(
    outcome: CheckOutcome | None,
) -> None:
    results: dict[str, CheckOutcome] = {"dns": dns_result()}
    if outcome is not None:
        results["reputation"] = outcome
    assert fire(RULE, host(HOST, **results)) == []


def test_a_result_that_names_a_block_but_lacks_the_name_of_the_resolver_is_not_trusted() -> None:
    odd = CheckOutcome("ok", data={"resolvers": [{"verdict": "blocked"}, "nonsense", None]})
    assert fire(RULE, host(HOST, dns=dns_result(), reputation=odd)) == []


def test_the_rule_is_medium_or_high_and_reads_the_reputation_check_first() -> None:
    rule = RULES[RULE]
    assert rule.severities == ("medium", "high")
    assert rule.checks == ("reputation", "dns")  # the first is where the evidence link points


def test_the_ways_a_block_shows_read_as_words() -> None:
    assert render_value("block_how", ["nxdomain", "ede"]) == (
        "the name does not resolve for it, it says that the name is blocked"
    )
    assert render_value("block_how", ["unspecified_address"]).startswith("it answers 0.0.0.0")
