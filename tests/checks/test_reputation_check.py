"""The reputation check: what it makes of the answers of security resolvers. No network.

The answers are scripted. Where it matters they are real ones, recorded from Quad9 and Cloudflare's
1.1.1.2 on 2026-10-07 (wire format, in hex): a name each of them blocks, a name each of them
resolves, and a name with broken DNSSEC (which fails, and is not a block).
"""

from __future__ import annotations

import json
from typing import Any

import dns.edns
import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.reputation import (
    ATTEMPTS,
    MAX_ANSWERS,
    SECURITY_RESOLVERS,
    ReputationCheck,
    ResolverHealth,
    baseline_of,
    judge,
)
from app.config import REPUTATION_RESOLVER_KEYS
from runner.dns import ip_block_reason

HOST = "www.example.com"
QUAD9 = "9.9.9.9"
CLOUDFLARE = "1.1.1.2"
CONFIG: dict[str, Any] = {
    "REPUTATION_RESOLVERS": ["quad9", "cloudflare"],
    "DNS_TIMEOUT_SECONDS": 5.0,
}

# Real answers, recorded 2026-10-07 (examplemalwaredomain.com, example.com, dnssec-failed.org at
# Quad9; malware.testcategory.com, example.com, dnssec-failed.org at 1.1.1.2).
QUAD9_BLOCKED = (
    "007f81030001000000000001146578616d706c656d616c77617265646f6d61696e03636f6d00000100010000"
    "2904d0000000000006000f00020011"
)
QUAD9_CLEAR = (
    "395481800001000200000001076578616d706c6503636f6d0000010001c00c00010001000000840004ac4293f3"
    "c00c000100010000008400046814179a0000290200000000000000"
)
QUAD9_DNSSEC_BOGUS = (
    "a74a818200010000000000010d646e737365632d6661696c6564036f726700000100010000290200000000000006"
    "000f00020007"
)
CLOUDFLARE_BLOCKED = (
    "0e7481800001000100000001076d616c776172650c7465737463617465676f727903636f6d0000010001c00c0001"
    "00010000003c00040000000000002904d0000000000006000f00020010"
)
CLOUDFLARE_BLOCKED_AAAA = (
    "e1e981800001000100000001076d616c776172650c7465737463617465676f727903636f6d00001c0001c00c001c"
    "00010000003c00100000000000000000000000000000000000002904d0000000000006000f00020010"
)
CLOUDFLARE_CLEAR = (
    "a18581800001000200000001076578616d706c6503636f6d0000010001c00c00010001000000810004ac4293f3"
    "c00c000100010000008100046814179a00002904d0000000000000"
)
CLOUDFLARE_DNSSEC_BOGUS = (
    "8872818200010000000000010d646e737365632d6661696c6564036f7267000001000100002904d000000000"
    "0039000f003500096e6f20534550206d61746368696e672074686520445320666f756e6420666f7220646e7373"
    "65632d6661696c65642e6f72672e"
)


def wire(text: str) -> dns.message.Message:
    return dns.message.from_wire(bytes.fromhex(text))


def reply(
    rcode: int = dns.rcode.NOERROR,
    answers: tuple[str, ...] = (),
    ede: tuple[int, ...] = (),
    rdtype: str = "A",
) -> dns.message.Message:
    """A synthetic answer: what a resolver says in a case the recordings do not cover."""
    query = dns.message.make_query(HOST, rdtype, use_edns=0)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    if answers:
        response.answer.append(dns.rrset.from_text(HOST + ".", 60, "IN", rdtype, *answers))
    if ede:
        response.use_edns(0, options=[dns.edns.EDEOption(code) for code in ede])
    return response


class Network:
    """Scripted resolvers: ``replies`` maps an address to an answer, an exception, or a list of
    them (one per question). Every question is recorded."""

    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = {key: list(v) if isinstance(v, list) else [v] for key, v in replies.items()}
        self.asked: list[tuple[str, str, str, float]] = []

    def __call__(self, query: dns.message.Message, address: str, timeout: float) -> Any:
        question = query.question[0]
        self.asked.append(
            (address, question.name.to_text(), dns.rdatatype.to_text(question.rdtype), timeout)
        )
        queue = self.replies[address]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item


class Slot:
    """A rate limiter that counts instead of waiting."""

    def __init__(self) -> None:
        self.taken = 0

    def acquire(self) -> float:
        self.taken += 1
        return 0.0


def dns_result(a: tuple[str, ...] = ("93.184.216.34",), aaaa: tuple[str, ...] = ()) -> CheckOutcome:
    return CheckOutcome(
        "ok",
        data={
            "a": [{"ip": ip, "ttl": 300} for ip in a],
            "aaaa": [{"ip": ip, "ttl": 300} for ip in aaaa],
            "addresses": [*a, *aaaa],
        },
    )


def run(
    network: Network,
    *,
    dns: CheckOutcome | None = None,
    config: dict[str, Any] | None = None,
    health: ResolverHealth | None = None,
    host: str = HOST,
    slots: dict[str, Slot] | None = None,
) -> CheckOutcome:
    table = slots if slots is not None else {}
    check = ReputationCheck(
        exchange=network,
        health=health or ResolverHealth(),
        limiter=lambda key: table.setdefault(key, Slot()),
    )
    ctx = CheckContext(
        domain="example.com",
        hostname=host,
        config={**CONFIG, **(config or {})},
        http=httpx.Client(),
        previous={"dns": dns or dns_result()},
    )
    return check.run(ctx)


def both(quad9: Any, cloudflare: Any) -> Network:
    return Network({QUAD9: quad9, CLOUDFLARE: cloudflare})


# ------------------------------------------------------------------------ what an answer says


@pytest.mark.parametrize(
    ("recorded", "verdict", "how", "ede", "error"),
    [
        (QUAD9_BLOCKED, "blocked", "nxdomain", [17], None),  # Quad9: NXDOMAIN, "Filtered"
        (CLOUDFLARE_BLOCKED, "blocked", "unspecified_address", [16], None),  # 0.0.0.0, "Censored"
        (CLOUDFLARE_BLOCKED_AAAA, "blocked", "unspecified_address", [16], None),  # and ::
        (QUAD9_CLEAR, "clear", None, [], None),
        (CLOUDFLARE_CLEAR, "clear", None, [], None),
        (QUAD9_DNSSEC_BOGUS, "unknown", None, [7], "servfail"),  # fails: not a block
        (CLOUDFLARE_DNSSEC_BOGUS, "unknown", None, [9], "servfail"),
    ],
)
def test_the_recorded_answers_of_the_real_resolvers_are_judged(
    recorded: str, verdict: str, how: str | None, ede: list[int], error: str | None
) -> None:
    fact = judge(wire(recorded), ["93.184.216.34"])
    assert (fact["verdict"], fact["how"], fact["ede"], fact["error"]) == (verdict, how, ede, error)


def test_a_clear_answer_keeps_the_addresses_it_gave() -> None:
    fact = judge(wire(QUAD9_CLEAR), ["93.184.216.34"])
    assert fact["answers"] == ["172.66.147.243", "104.20.23.154"] and fact["rcode"] == "NOERROR"


def test_a_sinkhole_address_is_a_block_only_against_a_name_that_resolves() -> None:
    zero = reply(answers=("0.0.0.0",))
    assert judge(zero, ["93.184.216.34"])["how"] == "unspecified_address"
    assert judge(zero, ["93.184.216.34"])["verdict"] == "blocked"  # no Extended DNS Error needed
    again = judge(zero, ["0.0.0.0"])  # the host resolves to nothing usable everywhere
    assert (again["verdict"], again["how"]) == ("clear", None)


@pytest.mark.parametrize("code", [15, 16, 17, 18])
def test_every_extended_error_that_says_blocked_counts(code: int) -> None:
    fact = judge(reply(answers=("93.184.216.34",), ede=(code,)), ["93.184.216.34"])
    assert (fact["verdict"], fact["how"]) == ("blocked", "ede")  # it resolved, yet it says blocked


@pytest.mark.parametrize(
    ("answer", "error"),
    [
        (reply(dns.rcode.NXDOMAIN), "nxdomain_unexplained"),  # nobody says why: not a block
        (reply(dns.rcode.NXDOMAIN, ede=(3,)), "nxdomain_unexplained"),  # an unrelated error code
        (reply(dns.rcode.SERVFAIL), "servfail"),
        (reply(dns.rcode.REFUSED), "resolver_refused"),
        (reply(), "no_answer"),  # the name exists but no address came back
        (reply(dns.rcode.FORMERR), "unexpected_rcode"),
    ],
)
def test_an_answer_that_settles_nothing_is_unknown_never_a_block(
    answer: dns.message.Message, error: str
) -> None:
    fact = judge(answer, ["93.184.216.34"])
    assert (fact["verdict"], fact["how"], fact["error"]) == ("unknown", None, error)


def test_what_an_answer_lists_is_bounded() -> None:
    many = tuple(f"192.0.2.{n}" for n in range(1, 21))
    assert len(judge(reply(answers=many), ["93.184.216.34"])["answers"]) == MAX_ANSWERS


# ---------------------------------------------------------------------------- the check


def test_a_host_that_both_resolvers_block_is_named_with_how_it_showed() -> None:
    network = both(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_BLOCKED))
    outcome = run(network)
    assert (outcome.status, outcome.source) == ("ok", "security-dns:quad9,cloudflare")
    data = outcome.data
    assert data["blocked_by"] == ["Quad9", "Cloudflare (1.1.1.2)"] and data["decided"] == 2
    quad9, cloudflare = data["resolvers"]
    assert (quad9["address"], quad9["how"], quad9["rcode"], quad9["ede"]) == (
        QUAD9,
        "nxdomain",
        "NXDOMAIN",
        [17],
    )
    assert (cloudflare["how"], cloudflare["answers"], cloudflare["ede"]) == (
        "unspecified_address",
        ["0.0.0.0"],
        [16],
    )
    assert (data["asked"], data["baseline"], data["host"]) == ("A", ["93.184.216.34"], HOST)


def test_a_host_that_neither_blocks_is_ok_with_nobody_named() -> None:
    outcome = run(both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR)))
    assert outcome.status == "ok" and outcome.data["blocked_by"] == []
    assert [r["verdict"] for r in outcome.data["resolvers"]] == ["clear", "clear"]


def test_one_resolver_blocking_and_the_other_not_names_the_first_only() -> None:
    outcome = run(both(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_CLEAR)))
    assert outcome.data["blocked_by"] == ["Quad9"] and outcome.data["decided"] == 2


def test_answers_that_settle_nothing_are_no_data_and_say_why() -> None:
    outcome = run(both(wire(QUAD9_DNSSEC_BOGUS), wire(CLOUDFLARE_DNSSEC_BOGUS)))
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_verdict")
    assert [r["error"] for r in outcome.data["resolvers"]] == ["servfail", "servfail"]
    assert outcome.data["blocked_by"] == [] and outcome.data["decided"] == 0


def test_a_resolver_that_does_not_answer_leaves_the_other_one_to_decide() -> None:
    network = both(dns.exception.Timeout(), wire(CLOUDFLARE_BLOCKED))
    outcome = run(network)
    assert outcome.status == "ok" and outcome.data["blocked_by"] == ["Cloudflare (1.1.1.2)"]
    quad9, cloudflare = outcome.data["resolvers"]
    assert (quad9["verdict"], quad9["error"]) == ("unknown", "timeout")
    assert cloudflare["verdict"] == "blocked"
    assert [a[0] for a in network.asked].count(QUAD9) == ATTEMPTS  # a lost packet is asked again


def test_when_no_resolver_answers_it_is_an_error_not_a_clean_host() -> None:
    outcome = run(both(dns.exception.Timeout(), dns.exception.Timeout()))
    assert (outcome.status, outcome.reason_code) == ("error", "no_resolver_answered")
    assert [r["error"] for r in outcome.data["resolvers"]] == ["timeout", "timeout"]
    assert outcome.data["blocked_by"] == [] and outcome.data["decided"] == 0
    unreachable = run(both(OSError("unreachable"), OSError("unreachable")))
    assert (unreachable.status, unreachable.reason_code) == ("error", "no_resolver_answered")
    assert [r["error"] for r in unreachable.data["resolvers"]] == ["network_error"] * 2


def test_a_network_error_is_not_asked_again_but_a_timeout_is() -> None:
    network = both(OSError("unreachable"), dns.exception.Timeout())
    run(network)
    assert [a[0] for a in network.asked] == [QUAD9, CLOUDFLARE, CLOUDFLARE]


def test_an_answer_from_the_wrong_source_or_garbled_is_a_bad_response() -> None:
    bad = dns.query.UnexpectedSource("answer from another address")
    outcome = run(both(bad, wire(CLOUDFLARE_CLEAR)))
    assert outcome.data["resolvers"][0]["error"] == "bad_response" and outcome.status == "ok"


def test_the_host_name_and_nothing_else_is_asked_of_the_enabled_resolvers() -> None:
    network = both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR))
    run(network, host="WWW.Example.COM.")
    assert network.asked == [
        (QUAD9, "www.example.com.", "A", 2.0),
        (CLOUDFLARE, "www.example.com.", "A", 2.0),
    ]


def test_only_the_resolvers_the_configuration_names_are_asked() -> None:
    network = Network({QUAD9: wire(QUAD9_CLEAR)})
    outcome = run(network, config={"REPUTATION_RESOLVERS": ["quad9"]})
    assert [a[0] for a in network.asked] == [QUAD9]
    assert outcome.source == "security-dns:quad9" and len(outcome.data["resolvers"]) == 1


def test_switched_off_it_asks_nobody_and_says_so() -> None:
    network = Network({})
    outcome = run(network, config={"REPUTATION_RESOLVERS": []})
    assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")
    assert network.asked == []


def test_a_host_with_no_address_record_has_nothing_to_compare_with() -> None:
    network = Network({})
    outcome = run(network, dns=dns_result(a=()))
    assert (outcome.status, outcome.reason_code) == ("skipped", "no_address_record")
    assert network.asked == []


def test_a_host_with_only_an_ipv6_address_is_asked_for_that() -> None:
    network = both(
        reply(answers=("2001:db8::1",), rdtype="AAAA"),
        wire(CLOUDFLARE_BLOCKED_AAAA),
    )
    outcome = run(network, dns=dns_result(a=(), aaaa=("2001:db8::1",)))
    assert {a[2] for a in network.asked} == {"AAAA"} and outcome.data["asked"] == "AAAA"
    assert outcome.data["blocked_by"] == ["Cloudflare (1.1.1.2)"]


def test_private_addresses_are_still_a_baseline_because_only_the_name_travels() -> None:
    outcome = run(
        both(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_CLEAR)), dns=dns_result(a=("10.0.0.5",))
    )
    assert outcome.status == "ok" and outcome.data["baseline"] == ["10.0.0.5"]


def test_a_name_that_cannot_be_asked_about_is_an_error_without_a_question() -> None:
    network = Network({})
    outcome = run(network, host="a" * 70 + ".example.com")
    assert (outcome.status, outcome.reason_code) == ("error", "invalid_name")
    assert network.asked == []


def test_each_question_takes_one_slot_of_the_rate_limit_of_its_resolver() -> None:
    slots: dict[str, Slot] = {}
    run(both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR)), slots=slots)
    run(both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR)), slots=slots)
    assert {key: slot.taken for key, slot in slots.items()} == {"quad9": 2, "cloudflare": 2}


def test_the_whole_result_is_plain_json() -> None:
    data = run(both(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_BLOCKED))).data
    assert json.loads(json.dumps(data)) == data


def test_the_check_is_a_host_check_that_needs_dns() -> None:
    check = ReputationCheck()
    assert (check.key, check.scope, check.needs) == ("reputation", "host", ("dns",))


# ------------------------------------------------------------- a resolver that stops answering


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_resolver_that_keeps_failing_is_left_alone_for_a_while_and_then_tried_again() -> None:
    clock = Clock()
    health = ResolverHealth(failures=3, pause=30.0, clock=clock)
    dead = Network({QUAD9: dns.exception.Timeout(), CLOUDFLARE: wire(CLOUDFLARE_CLEAR)})
    for _ in range(3):
        run(dead, health=health)
    asked_before = len(dead.asked)
    outcome = run(dead, health=health)
    assert len(dead.asked) == asked_before + 1  # only Cloudflare was asked
    assert outcome.data["resolvers"][0]["error"] == "resolver_paused"
    assert outcome.status == "ok"  # the other one decided

    clock.now += 31
    revived = Network({QUAD9: wire(QUAD9_CLEAR), CLOUDFLARE: wire(CLOUDFLARE_CLEAR)})
    assert run(revived, health=health).data["resolvers"][0]["verdict"] == "clear"
    assert health.allow("quad9")  # an answer clears the record of failures


def test_when_every_resolver_is_paused_the_check_fails_without_waiting() -> None:
    health = ResolverHealth(failures=1, pause=30.0, clock=Clock())
    timeouts = both(dns.exception.Timeout(), dns.exception.Timeout())
    run(timeouts, health=health)
    again = both(wire(QUAD9_CLEAR), wire(CLOUDFLARE_CLEAR))
    outcome = run(again, health=health)
    assert (outcome.status, outcome.reason_code) == ("error", "no_resolver_answered")
    assert again.asked == []


def test_the_pause_starts_only_after_the_failures_in_a_row() -> None:
    health = ResolverHealth(failures=3, pause=30.0, clock=Clock())
    health.record("quad9", False)
    health.record("quad9", False)
    health.record("quad9", True)  # an answer starts the count again
    health.record("quad9", False)
    health.record("quad9", False)
    assert health.allow("quad9")
    health.record("quad9", False)
    assert not health.allow("quad9") and health.allow("cloudflare")


# ------------------------------------------------------------------------- the registry


def test_the_resolvers_the_configuration_may_name_are_the_ones_the_check_knows() -> None:
    assert set(SECURITY_RESOLVERS) == set(REPUTATION_RESOLVER_KEYS)


def test_every_resolver_is_a_public_address_the_check_may_send_a_question_to() -> None:
    for resolver in SECURITY_RESOLVERS.values():
        assert ip_block_reason(resolver.address) is None, resolver
        assert resolver.name


def test_the_baseline_reads_the_a_records_then_the_aaaa_records() -> None:
    assert baseline_of(dns_result().data) == ("A", ["93.184.216.34"])
    assert baseline_of(dns_result(a=(), aaaa=("2001:db8::1",)).data) == ("AAAA", ["2001:db8::1"])
    assert baseline_of({"a": "nonsense", "aaaa": [None, {"ip": ""}]}) == (None, [])
    assert baseline_of({}) == (None, [])
