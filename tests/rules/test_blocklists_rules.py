"""The blocklist rules, over what the real blocklists check makes of scripted lists."""

from __future__ import annotations

from typing import Any

import pytest

from app.checks.base import CheckOutcome
from app.rules import RULES
from app.service.findings import render_value
from tests.checks.test_blocklists_check import (
    ALL_FEEDS,
    EVIL_ALIAS,
    HOST,
    IP1,
    IP2,
    FakeLists,
    feed,
)
from tests.checks.test_blocklists_check import run as run_blocklists
from tests.checks.test_ports_check import CLOUDFLARE, ip_outcome, located
from tests.checks.test_ports_check import dns as dns_with
from tests.rules.helpers import fire, host, one

NAME_RULE = "HOST_ON_BLOCKLIST"
ALIAS_RULE = "ALIAS_ON_BLOCKLIST"
ADDRESS_RULE = "HOST_ADDRESS_ON_BLOCKLIST"
ALL_RULES = (NAME_RULE, ALIAS_RULE, ADDRESS_RULE)


def judged(
    lists: FakeLists,
    *,
    dns: CheckOutcome | None = None,
    ip: CheckOutcome | None = None,
    **others: CheckOutcome,
) -> Any:
    """The host as the stored results of a scan would show it."""
    shown = dns or dns_with(IP1)
    results = {"dns": shown, "blocklists": run_blocklists(lists, dns=shown, ip=ip), **others}
    if ip is not None:
        results["ip"] = ip
    return host(HOST, **results)


def silent(subject: Any) -> bool:
    return all(fire(rule, subject) == [] for rule in ALL_RULES)


# ------------------------------------------------------------------------------ the host name


def test_a_host_name_on_the_malware_list_is_high_with_medium_confidence() -> None:
    subject = judged(FakeLists(names={HOST: ("urlhaus",)}))
    draft = one(NAME_RULE, subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "high",
        "medium",
        "hostname_supported",
    )
    assert draft.subject == f"host:{HOST}" and draft.host_id == subject.id
    assert draft.params == {
        "host": HOST,
        "lists": ["abuse.ch URLhaus (2026-10-07)"],
        "listed_for": ["malware"],
    }
    assert draft.evidence == (subject.results["blocklists"].id, subject.results["dns"].id)
    assert fire(ALIAS_RULE, subject) == [] and fire(ADDRESS_RULE, subject) == []


def test_two_lists_are_named_in_the_order_they_were_consulted() -> None:
    draft = one(NAME_RULE, judged(FakeLists(names={HOST: ("phishing", "urlhaus")})))
    assert draft.params["lists"] == [
        "abuse.ch URLhaus (2026-10-07)",
        "Phishing.Database (2026-10-07)",
    ]
    assert draft.params["listed_for"] == ["malware", "phishing"]


def test_only_the_lists_that_name_the_host_are_named() -> None:
    old = [feed("urlhaus", as_of="2026-10-02", stale=True), feed("phishing"), feed("feodo")]
    draft = one(NAME_RULE, judged(FakeLists(feeds=old, names={HOST: ("urlhaus",)})))
    assert draft.params["lists"] == ["abuse.ch URLhaus (2026-10-02)"]  # its own date, and no other


# ------------------------------------------------------------------------------ an alias


def test_an_alias_for_a_listed_name_is_medium() -> None:
    dns = dns_with(IP1, cname=EVIL_ALIAS)
    subject = judged(FakeLists(names={EVIL_ALIAS: ("phishing",)}), dns=dns)
    draft = one(ALIAS_RULE, subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "medium",
        "medium",
        "hostname_supported",
    )
    assert draft.params == {
        "host": HOST,
        "listed": [EVIL_ALIAS],
        "lists": ["Phishing.Database (2026-10-07)"],
        "listed_for": ["phishing"],
    }
    assert fire(NAME_RULE, subject) == []


def test_when_the_host_itself_is_listed_the_alias_adds_no_second_finding() -> None:
    lists = FakeLists(names={HOST: ("urlhaus",), EVIL_ALIAS: ("phishing",)})
    subject = judged(lists, dns=dns_with(IP1, cname=EVIL_ALIAS))
    assert len(fire(NAME_RULE, subject)) == 1 and fire(ALIAS_RULE, subject) == []


# ------------------------------------------------------------------------------ an address


def test_an_address_on_the_botnet_list_is_high_with_medium_confidence() -> None:
    subject = judged(FakeLists(addresses={IP1: ("feodo",)}))
    draft = one(ADDRESS_RULE, subject)
    assert (draft.severity, draft.confidence, draft.attribution) == ("high", "medium", "ip_only")
    assert draft.params == {
        "host": HOST,
        "addresses": [IP1],
        "lists": ["abuse.ch Feodo Tracker (2026-10-07)"],
        "listed_for": ["botnet"],
    }
    assert fire(NAME_RULE, subject) == [] and fire(ALIAS_RULE, subject) == []


def test_an_address_on_the_phishing_list_alone_is_medium_with_low_confidence() -> None:
    draft = one(ADDRESS_RULE, judged(FakeLists(addresses={IP1: ("phishing",)})))
    assert (draft.severity, draft.confidence) == ("medium", "low")
    assert draft.params["listed_for"] == ["phishing"]


def test_one_finding_names_every_listed_address_and_the_most_serious_list_decides() -> None:
    lists = FakeLists(addresses={IP1: ("phishing",), IP2: ("feodo",)})
    draft = one(ADDRESS_RULE, judged(lists, dns=dns_with(IP1, IP2, "203.0.113.9")))
    assert draft.params["addresses"] == [IP1, IP2]
    assert draft.params["listed_for"] == ["phishing", "botnet"]
    assert (draft.severity, draft.confidence) == ("high", "medium")


def test_an_address_on_a_cdn_edge_never_raises_the_rule_however_it_is_listed() -> None:
    lists = FakeLists(addresses={IP1: ("feodo", "phishing")})
    subject = judged(lists, ip=ip_outcome(located(IP1, CLOUDFLARE)))
    assert subject.results["blocklists"].data["addresses"][0]["shared"] is True
    assert silent(subject)


def test_a_shared_address_does_not_hide_the_listing_of_the_hosts_own_address() -> None:
    lists = FakeLists(addresses={IP1: ("phishing",), IP2: ("feodo",)})
    ip = ip_outcome(located(IP1, CLOUDFLARE), located(IP2, None))
    draft = one(ADDRESS_RULE, judged(lists, dns=dns_with(IP1, IP2), ip=ip))
    assert draft.params["addresses"] == [IP2] and draft.params["listed_for"] == ["botnet"]


# ------------------------------------------------------------------------------ nothing to say


def test_a_host_that_is_not_listed_anywhere_gets_no_finding() -> None:
    assert silent(judged(FakeLists()))


@pytest.mark.parametrize(
    "outcome",
    [
        None,
        CheckOutcome("unavailable", "blocklists_missing", {"host": HOST, "not_installed": ["x"]}),
        CheckOutcome("unavailable", "blocklists_unreadable"),
        CheckOutcome("skipped", "disabled"),
        CheckOutcome("error", "invalid_name"),
        CheckOutcome("no_data", "nothing"),
    ],
)
def test_without_a_result_of_the_check_that_answered_the_rules_stay_silent(
    outcome: CheckOutcome | None,
) -> None:
    results: dict[str, CheckOutcome] = {"dns": dns_with(IP1)}
    if outcome is not None:
        results["blocklists"] = outcome
    assert silent(host(HOST, **results))


def test_a_result_with_rows_that_name_a_listing_without_the_rest_is_not_trusted() -> None:
    odd = CheckOutcome(
        "ok",
        data={
            "feeds": ["nonsense", None],
            "names": [{"role": "host"}, "nonsense", {"role": "host", "listed_on": ["nobody"]}],
            "addresses": [{"ip": IP1, "listed_on": ["nobody"], "shared": False}, None],
        },
    )
    # a listing by a list that is not among the consulted ones names no list: nothing to report
    assert silent(host(HOST, dns=dns_with(IP1), blocklists=odd))


def test_the_rules_say_what_they_can_produce_and_read_the_blocklists_check_first() -> None:
    assert RULES[NAME_RULE].severities == ("high",)
    assert RULES[ALIAS_RULE].severities == ("medium",)
    assert RULES[ADDRESS_RULE].severities == ("medium", "high")
    for rule in ALL_RULES:
        assert RULES[rule].checks == ("blocklists", "dns")  # the first is where the evidence points
        assert RULES[rule].scope == "host"


def test_the_kinds_of_list_read_as_words() -> None:
    assert render_value("listed_for", ["malware", "phishing", "botnet"]) == (
        "serving malware, phishing, controlling a botnet"
    )
    assert render_value("listed_for", ["something_new"]) == "something_new"


def test_every_provider_of_the_check_has_a_kind_the_rules_know() -> None:
    assert {f.kind for f in ALL_FEEDS} == {"malware", "phishing", "botnet"}
