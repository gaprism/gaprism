"""The blocklists check: what it asks the installed lists and what it makes of their answers.

The lists are scripted here (``FakeLists``); a few tests build small real files instead, to show
that the check and the service fit together. No network: the check never uses the HTTP client.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx

from app.checks import REGISTRY, waits_for
from app.checks.base import CheckContext, CheckOutcome
from app.checks.blocklists import MAX_NAMES, BlocklistsCheck, names_to_ask, network_of
from app.service.blocklists import (
    PROVIDERS,
    FeedState,
    Listings,
    Snapshot,
    build_database,
)
from app.service.host_view import CHECK_ORDER, CHECK_TITLES
from tests.checks.test_ports_check import AWS, CLOUDFLARE, ip_outcome, located
from tests.checks.test_ports_check import dns as dns_with

HOST = "www.example.com"
IP1, IP2 = "93.184.216.34", "93.184.216.35"
EVIL_ALIAS = "login.evil-example.net"
NOW = date(2026, 10, 7)


def no_http(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"the blocklists check must not use the network: {request.url}")


HTTP = httpx.Client(transport=httpx.MockTransport(no_http))


def feed(
    key: str,
    *,
    as_of: str = "2026-10-07",
    stale: bool = False,
    domains: int = 1200,
    addresses: int = 30,
) -> FeedState:
    provider = PROVIDERS[key]
    return FeedState(key, provider.name, provider.kind, as_of, as_of, domains, addresses, stale)


ALL_FEEDS = tuple(feed(key) for key in PROVIDERS)


class FakeLists:
    """Installed lists from a table: ``names`` and ``addresses`` map a value to the providers that
    list it. Remembers what it was asked."""

    def __init__(
        self,
        feeds: Iterable[FeedState] = ALL_FEEDS,
        names: dict[str, tuple[str, ...]] | None = None,
        addresses: dict[str, tuple[str, ...]] | None = None,
        unreadable: Collection[str] = (),
        failing: Collection[str] = (),
    ) -> None:
        self.feeds = tuple(feeds)
        self.names = names or {}
        self.addresses = addresses or {}
        self.unreadable = tuple(unreadable)  # a file is there but was unreadable when it was loaded
        self.failing = tuple(failing)  # loaded fine, but fails when it is read for a lookup
        self.snapshots: list[Collection[str] | None] = []
        self.lookups: list[tuple[list[str], list[str], Collection[str] | None]] = []

    def snapshot(self, today: date | None = None, only: Collection[str] | None = None) -> Snapshot:
        self.snapshots.append(only)
        wanted = [f for f in self.feeds if only is None or f.key in only]
        broken = tuple(k for k in self.unreadable if only is None or k in only)
        return Snapshot(tuple(wanted), broken)

    def lookup(
        self, names: Iterable[str], addresses: Iterable[str], only: Collection[str] | None = None
    ) -> Listings:
        asked_names, asked_addresses = list(names), list(addresses)
        self.lookups.append((asked_names, asked_addresses, only))
        usable = {f.key for f in self.feeds if only is None or f.key in only} - set(self.failing)

        def keep(
            table: dict[str, tuple[str, ...]], values: list[str]
        ) -> dict[str, tuple[str, ...]]:
            found = {v: tuple(k for k in table[v] if k in usable) for v in values if v in table}
            return {v: keys for v, keys in found.items() if keys}

        return Listings(
            keep(self.names, asked_names),
            keep(self.addresses, asked_addresses),
            tuple(k for k in self.failing if only is None or k in only),
        )


def run(
    lists: Any = None,
    *,
    dns: CheckOutcome | None = None,
    ip: CheckOutcome | None = None,
    config: dict[str, Any] | None = None,
    host: str | None = HOST,
) -> CheckOutcome:
    chosen = lists if lists is not None else FakeLists()
    previous = {"dns": dns or dns_with(IP1)}
    if ip is not None:
        previous["ip"] = ip
    ctx = CheckContext(
        domain="example.com",
        hostname=host,
        config=config if config is not None else {"BLOCKLIST_PROVIDERS": list(PROVIDERS)},
        http=HTTP,
        previous=previous,
    )
    return BlocklistsCheck(data_factory=lambda _ctx: chosen).run(ctx)


def asked_about(data: dict[str, Any], section: str) -> list[str]:
    return [str(row["name"] if section == "names" else row["ip"]) for row in data[section]]


def test_the_check_is_registered_for_every_host_after_dns_and_ip() -> None:
    check = REGISTRY["blocklists"]
    assert (check.scope, check.needs, waits_for(check)) == ("host", ("dns",), ("dns", "ip"))
    assert "blocklists" in CHECK_ORDER and "blocklists" in CHECK_TITLES  # the pages show it


# ------------------------------------------------------------------------------ what it asks


def test_the_host_its_aliases_and_its_addresses_are_looked_up() -> None:
    lists = FakeLists()
    outcome = run(lists, dns=dns_with(IP1, IP2, cname=EVIL_ALIAS))
    assert outcome.status == "ok"
    assert lists.lookups == [([HOST, EVIL_ALIAS], [IP1, IP2], ["urlhaus", "phishing", "feodo"])]
    assert [(n["name"], n["role"]) for n in outcome.data["names"]] == [
        (HOST, "host"),
        (EVIL_ALIAS, "alias"),
    ]
    assert asked_about(outcome.data, "addresses") == [IP1, IP2]


def test_the_names_are_exact_names_without_duplicates_and_bounded() -> None:
    steps = [{"name": f"a{n}.example.net", "target": f"a{n + 1}.example.net"} for n in range(12)]
    shown = {
        "addresses": [],
        "cname": [
            *steps,
            {"name": "x", "target": HOST.upper()},
            {"name": "y", "target": "not a name"},
        ],
        "canonical_name": "a12.example.net",
    }
    asked = names_to_ask(HOST, shown)
    assert asked[0] == (HOST, "host") and len(asked) == MAX_NAMES
    assert [role for _, role in asked] == ["host"] + ["alias"] * (MAX_NAMES - 1)
    assert (
        len({name for name, _ in asked}) == MAX_NAMES
    )  # the host is not asked twice (HOST.upper())
    assert names_to_ask(HOST, {}) == [(HOST, "host")]


def test_a_parent_domain_is_not_asked_about() -> None:
    lists = FakeLists()
    deep = "a.b.shop.example.com"
    own = CheckOutcome("ok", data={"addresses": [IP1], "cname": [], "canonical_name": deep})
    run(lists, host=deep, dns=own)
    assert lists.lookups[0][0] == [deep]  # not shop.example.com or example.com


def test_at_most_eight_addresses_are_asked_and_the_rest_is_counted() -> None:
    many = [f"203.0.113.{n}" for n in range(1, 13)]
    lists = FakeLists()
    outcome = run(lists, dns=dns_with(*many))
    assert lists.lookups[0][1] == many[:8]
    assert (outcome.data["addresses_total"], outcome.data["truncated"]) == (12, True)
    assert run(dns=dns_with(IP1)).data["truncated"] is False


def test_a_host_without_public_addresses_is_still_asked_by_name() -> None:
    outcome = run(dns=dns_with())
    assert outcome.status == "ok" and outcome.data["addresses"] == []
    assert outcome.data["addresses_total"] == 0 and outcome.data["names"][0]["name"] == HOST


def test_the_name_is_normalised_and_a_name_that_is_none_is_an_error() -> None:
    assert run(host="WWW.Example.COM.").data["host"] == HOST
    for bad in (None, "", "not a host", "localhost"):
        outcome = run(host=bad)
        assert (outcome.status, outcome.reason_code) == ("error", "invalid_name")


# ------------------------------------------------------------------------------ what it finds


def test_nothing_listed_is_an_answer_that_says_which_lists_were_consulted() -> None:
    outcome = run()
    assert (outcome.status, outcome.reason_code) == ("ok", None)
    assert outcome.source == "blocklists:feodo,phishing,urlhaus"
    assert [f["key"] for f in outcome.data["feeds"]] == ["urlhaus", "phishing", "feodo"]
    assert outcome.data["feeds"][0]["as_of"] == "2026-10-07"
    assert outcome.data["not_installed"] == [] and outcome.data["unreadable"] == []
    assert outcome.data["names"][0]["listed_on"] == []
    assert outcome.data["addresses"][0]["listed_on"] == []


def test_a_listed_host_name_shows_with_the_providers_in_a_fixed_order() -> None:
    lists = FakeLists(names={HOST: ("phishing", "urlhaus")})
    outcome = run(lists)
    assert outcome.data["names"][0] == {
        "name": HOST,
        "role": "host",
        "listed_on": ["urlhaus", "phishing"],
    }


def test_a_listed_alias_target_is_found_as_an_alias() -> None:
    outcome = run(FakeLists(names={EVIL_ALIAS: ("phishing",)}), dns=dns_with(IP1, cname=EVIL_ALIAS))
    host, alias = outcome.data["names"]
    assert host["listed_on"] == [] and (alias["role"], alias["listed_on"]) == (
        "alias",
        ["phishing"],
    )


def test_a_listed_address_is_found_whatever_the_form_of_its_text() -> None:
    lists = FakeLists(addresses={"2001:db8::1": ("feodo",), IP1: ("feodo", "phishing")})
    outcome = run(lists, dns=dns_with(IP1, "2001:0DB8:0:0:0:0:0:1"))
    first, second = outcome.data["addresses"]
    assert first["listed_on"] == ["phishing", "feodo"] and first["shared"] is False
    assert second["ip"] == "2001:0DB8:0:0:0:0:0:1"  # as the DNS check wrote it
    assert second["listed_on"] == ["feodo"]  # asked as "2001:db8::1", the one form the lists use
    assert lists.lookups[0][1] == [IP1, "2001:db8::1"]


def test_the_real_lookup_normalises_addresses_so_any_form_finds_them(tmp_path: Path) -> None:
    install(tmp_path, "feodo", addresses="2001:db8::1\n# END 1 entries\n")
    outcome = run_real(tmp_path, dns=dns_with("2001:0DB8:0:0:0:0:0:1"))
    assert outcome.data["addresses"][0]["listed_on"] == ["feodo"]


def test_a_listed_address_on_a_cdn_edge_is_marked_shared() -> None:
    lists = FakeLists(addresses={IP1: ("phishing",)})
    outcome = run(lists, ip=ip_outcome(located(IP1, CLOUDFLARE)))
    row = outcome.data["addresses"][0]
    assert (row["listed_on"], row["shared"], row["network"]["name"]) == (
        ["phishing"],
        True,
        "Cloudflare",
    )


def test_a_cloud_address_is_not_an_edge_and_still_counts() -> None:
    lists = FakeLists(addresses={IP1: ("feodo",)})
    row = run(lists, ip=ip_outcome(located(IP1, AWS))).data["addresses"][0]
    assert (row["listed_on"], row["shared"], row["network"]["kind"]) == (["feodo"], False, "cloud")


def test_the_cname_chain_reveals_an_edge_when_the_ip_check_did_not_run() -> None:
    lists = FakeLists(addresses={IP1: ("phishing",)})
    outcome = run(
        lists, dns=dns_with(IP1, cname="d111111abcdef8.cloudfront.net")
    )  # no "ip" outcome
    row = outcome.data["addresses"][0]
    assert (row["shared"], row["network"]["name"]) == (True, "Amazon CloudFront")
    assert outcome.data["names"][1]["name"] == "d111111abcdef8.cloudfront.net"


def test_the_network_hint_prefers_the_ip_check_and_ignores_a_failed_one() -> None:
    assert network_of(IP1, ip_outcome(located(IP1, CLOUDFLARE)), []) == CLOUDFLARE
    failed = CheckOutcome("unavailable", "geo_missing", {"addresses": [IP1]})
    assert network_of(IP1, failed, []) is None
    assert network_of(IP1, None, ["x.fastly.net"]) is not None
    assert network_of(IP2, ip_outcome(located(IP1, CLOUDFLARE)), []) is None


# ------------------------------------------------------------------------------ what it cannot do


def test_nothing_installed_is_unavailable_not_a_clean_answer() -> None:
    outcome = run(FakeLists(feeds=()))
    assert (outcome.status, outcome.reason_code) == ("unavailable", "blocklists_missing")
    assert outcome.data["not_installed"] == ["urlhaus", "phishing", "feodo"]
    assert "names" not in outcome.data and outcome.source == "blocklists"


def test_files_that_cannot_be_read_are_unavailable_too_with_their_own_reason() -> None:
    outcome = run(FakeLists(feeds=(), unreadable=["urlhaus", "feodo"]))
    assert (outcome.status, outcome.reason_code) == ("unavailable", "blocklists_unreadable")
    assert outcome.data["unreadable"] == ["urlhaus", "feodo"]
    assert outcome.data["not_installed"] == ["phishing"]


def test_a_missing_list_does_not_stop_the_others_and_is_named() -> None:
    lists = FakeLists(feeds=[feed("urlhaus")], names={HOST: ("urlhaus", "phishing")})
    outcome = run(lists)
    assert outcome.status == "ok" and outcome.source == "blocklists:urlhaus"
    assert outcome.data["not_installed"] == ["phishing", "feodo"]
    assert outcome.data["names"][0]["listed_on"] == ["urlhaus"]


def test_a_list_that_fails_during_the_lookup_is_not_counted_as_consulted() -> None:
    lists = FakeLists(
        names={HOST: ("urlhaus", "phishing")}, addresses={IP1: ("feodo",)}, failing=["phishing"]
    )
    outcome = run(lists)
    assert outcome.status == "ok" and outcome.data["unreadable"] == ["phishing"]
    assert [f["key"] for f in outcome.data["feeds"]] == ["urlhaus", "feodo"]
    assert outcome.data["names"][0]["listed_on"] == ["urlhaus"]
    assert outcome.data["not_installed"] == []
    everything_failing = run(FakeLists(failing=list(PROVIDERS)))
    assert (everything_failing.status, everything_failing.reason_code) == (
        "unavailable",
        "blocklists_unreadable",
    )


def test_an_old_list_is_reported_as_old_and_still_used() -> None:
    old = [feed("urlhaus", as_of="2026-09-20", stale=True), feed("feodo")]
    outcome = run(FakeLists(feeds=old, names={HOST: ("urlhaus",)}))
    assert [(f["key"], f["stale"]) for f in outcome.data["feeds"]] == [
        ("urlhaus", True),
        ("feodo", False),
    ]
    assert outcome.data["names"][0]["listed_on"] == ["urlhaus"]


# ------------------------------------------------------------------------------ the owner's choice


def test_switched_off_is_skipped_as_a_decision_and_the_lists_are_not_touched() -> None:
    lists = FakeLists()
    outcome = run(lists, config={"BLOCKLIST_PROVIDERS": []})
    assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")
    assert lists.snapshots == [] and lists.lookups == []


def test_only_the_chosen_providers_are_used_and_unknown_names_are_ignored() -> None:
    lists = FakeLists(names={HOST: ("urlhaus", "feodo")})
    outcome = run(lists, config={"BLOCKLIST_PROVIDERS": ["feodo", "carrier-pigeon"]})
    assert lists.snapshots == [["feodo"]] and lists.lookups[0][2] == ["feodo"]
    assert [f["key"] for f in outcome.data["feeds"]] == ["feodo"]
    assert outcome.data["names"][0]["listed_on"] == ["feodo"]
    assert run(config={"BLOCKLIST_PROVIDERS": ["carrier-pigeon"]}).reason_code == "disabled"


def test_a_configuration_that_does_not_say_uses_all_the_providers() -> None:
    lists = FakeLists()
    run(lists, config={})
    assert lists.snapshots == [["urlhaus", "phishing", "feodo"]]


# ------------------------------------------------------------------------------ with real files


def install(directory: Path, key: str, **texts: str) -> None:
    provider = PROVIDERS[key]
    downloads = {}
    for kind, text in texts.items():
        downloads[kind] = directory / f"{key}-{kind}.txt"
        downloads[kind].write_text(text, encoding="utf-8")
    now = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    build_database(provider, downloads, directory / provider.filename, now, relaxed=True)


def run_real(
    directory: Path, *, dns: CheckOutcome | None = None, config: dict[str, Any] | None = None
) -> CheckOutcome:
    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config={"DATASETS_DIR": str(directory), **(config or {})},
        http=HTTP,
        previous={"dns": dns or dns_with(IP1, cname=EVIL_ALIAS)},
    )
    return BlocklistsCheck().run(ctx)  # the default: the shared reader of the directory


def test_the_check_reads_the_files_that_the_service_built(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains=f"{HOST}\n")
    install(tmp_path, "phishing", domains=f"{EVIL_ALIAS}\n", addresses=f"{IP1}\n")
    install(tmp_path, "feodo", addresses=f"{IP2}\n# END 1 entries\n")
    outcome = run_real(tmp_path, dns=dns_with(IP1, IP2, cname=EVIL_ALIAS))
    assert outcome.status == "ok"
    host, alias = outcome.data["names"]
    assert (host["listed_on"], alias["listed_on"]) == (["urlhaus"], ["phishing"])
    first, second = outcome.data["addresses"]
    assert (first["listed_on"], second["listed_on"]) == (["phishing"], ["feodo"])
    assert [f["key"] for f in outcome.data["feeds"]] == ["urlhaus", "phishing", "feodo"]


def test_no_directory_or_an_empty_one_means_nothing_is_installed(tmp_path: Path) -> None:
    for config in ({}, {"DATASETS_DIR": ""}):
        ctx = CheckContext("example.com", HOST, config, HTTP, {"dns": dns_with(IP1)})
        outcome = BlocklistsCheck().run(ctx)
        assert (outcome.status, outcome.reason_code) == ("unavailable", "blocklists_missing")
    assert run_real(tmp_path).reason_code == "blocklists_missing"


def test_a_file_that_is_not_a_database_is_reported_as_unreadable(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains=f"{HOST}\n")
    (tmp_path / "feodo.sqlite").write_bytes(b"not a database" * 40)
    outcome = run_real(tmp_path, config={"BLOCKLIST_PROVIDERS": ["urlhaus", "feodo"]})
    assert outcome.status == "ok" and outcome.data["unreadable"] == ["feodo"]
    assert outcome.data["names"][0]["listed_on"] == ["urlhaus"]
    only_bad = run_real(tmp_path, config={"BLOCKLIST_PROVIDERS": ["feodo"]})
    assert only_bad.reason_code == "blocklists_unreadable"
