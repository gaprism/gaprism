"""The ports check: typed outcomes, attribution, caching, bounds. No network, no database."""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from app.checks.base import CachedAnswer, CheckContext, CheckOutcome, waits_for
from app.checks.ports import MAX_ADDRESSES, PortsCheck, attribute
from app.service.ports import PortFacts, PortService, PortsLookup, PortsProvider, Vulnerability

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
HOST = "www.example.com"
IP1, IP2, IP3 = "93.184.216.34", "93.184.216.35", "2606:2800:220:1::1"
KEY = "SECRET-KEY-0123456789"
HTTP = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))


class FakeProvider:
    """Answers from a table; remembers what it was asked."""

    name = "shodan"

    def __init__(
        self, answers: dict[str, PortsLookup] | None = None, default: PortsLookup | None = None
    ):
        self.answers = answers or {}
        self.default = default or PortsLookup("no_data", "no_information")
        self.calls: list[str] = []

    def lookup(self, ip: str) -> PortsLookup:
        self.calls.append(ip)
        return self.answers.get(ip, self.default)


class FakeCache:
    """An in-memory ``CacheStore`` that honours ``max_age`` against a movable clock."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], CachedAnswer] = {}
        self.puts: list[tuple[str, str, str]] = []
        self.now = NOW

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None:
        row = self.rows.get((provider, key))
        return None if row is None or row.fetched_at < self.now - max_age else row

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None:
        self.puts.append((provider, key, status))
        self.rows[(provider, key)] = CachedAnswer(status, payload, self.now)


def facts(
    ip: str = IP1,
    ports: tuple[int, ...] = (80, 443),
    cves: tuple[str, ...] = (),
    **fields: Any,
) -> PortFacts:
    return PortFacts(
        ip=ip,
        provider=fields.pop("provider", "shodan"),
        services=tuple(PortService(port) for port in ports),
        vulnerabilities=tuple(Vulnerability(cve) for cve in cves),
        **fields,
    )


def found(ip: str = IP1, **kwargs: Any) -> PortsLookup:
    return PortsLookup("ok", facts=facts(ip, **kwargs))


def dns(*addresses: str, cname: str | None = None) -> CheckOutcome:
    steps = [{"name": HOST, "target": cname}] if cname else []
    return CheckOutcome(
        "ok", data={"addresses": list(addresses), "cname": steps, "canonical_name": cname or HOST}
    )


def located(
    ip: str, network: dict[str, Any] | None = None, asn: int | None = None
) -> dict[str, Any]:
    return {"ip": ip, "asn": asn, "network": network}


def ip_outcome(*entries: dict[str, Any], status: str = "ok") -> CheckOutcome:
    return CheckOutcome(status, data={"addresses": list(entries)})  # type: ignore[arg-type]


CLOUDFLARE = {"name": "Cloudflare", "kind": "cdn", "edge": True}
AWS = {"name": "Amazon Web Services", "kind": "cloud", "edge": False}


def run(
    provider: PortsProvider | str,
    previous: dict[str, CheckOutcome],
    *,
    config: dict[str, Any] | None = None,
    cache: FakeCache | None = None,
    hostname: str | None = HOST,
    exploits: Any = None,
) -> CheckOutcome:
    check = PortsCheck(
        provider_factory=lambda ctx: provider,
        clock=lambda: NOW,
        exploit_factory=(lambda ctx: exploits) if exploits is not None else None,
    )
    ctx = CheckContext(
        domain="example.com",
        hostname=hostname,
        config=config or {},
        http=HTTP,
        previous=previous,
        cache=cache,
    )
    return check.run(ctx)


# ------------------------------------------------------------------------------ contract


def test_it_needs_dns_and_follows_the_ip_check_without_needing_it() -> None:
    check = PortsCheck()
    assert (check.key, check.scope) == ("ports", "host")
    assert check.needs == ("dns",) and check.after == ("ip",)
    assert waits_for(check) == ("dns", "ip")


def test_without_a_public_address_there_is_nothing_to_ask() -> None:
    provider = FakeProvider()
    for previous in ({}, {"dns": dns()}):
        outcome = run(provider, previous)
        assert (outcome.status, outcome.reason_code) == ("skipped", "no_public_address")
    assert provider.calls == []


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("disabled", "skipped"),  # the owner switched it off: a decision, not a gap
        ("missing_api_key", "unavailable"),  # a setting that cannot work: a gap
    ],
)
def test_an_unconfigured_provider_is_never_a_clean_result(reason: str, status: str) -> None:
    outcome = run(reason, {"dns": dns(IP1, IP2)})
    assert (outcome.status, outcome.reason_code) == (status, reason)
    assert outcome.data == {"addresses_total": 2}


# ------------------------------------------------------------------------------ results


def test_a_known_address_is_reported_with_its_ports_cves_and_when() -> None:
    provider = FakeProvider({IP1: found(ports=(22, 443), cves=("CVE-2021-23017",))})
    outcome = run(provider, {"dns": dns(IP1)})

    assert (outcome.status, outcome.reason_code, outcome.source) == ("ok", None, "shodan")
    assert outcome.data["provider"] == "shodan" and outcome.data["complete"] is True
    assert (outcome.data["addresses_total"], outcome.data["truncated"]) == (1, False)
    (entry,) = outcome.data["addresses"]
    assert (entry["ip"], entry["status"], entry["cached"]) == (IP1, "ok", False)
    assert entry["fetched_at"] == NOW.isoformat()
    assert entry["facts"]["ports"] == [22, 443]
    assert [vuln["id"] for vuln in entry["facts"]["vulnerabilities"]] == ["CVE-2021-23017"]
    assert entry["attribution"] == "ip_only" and entry["attribution_basis"] == []
    json.dumps(outcome.data)  # it must be storable as JSON


def test_an_address_the_provider_does_not_know_is_no_data_not_clean() -> None:
    outcome = run(FakeProvider(), {"dns": dns(IP1, IP2)})
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_information")
    assert [entry["status"] for entry in outcome.data["addresses"]] == ["no_data", "no_data"]


def test_one_unknown_and_one_known_address_is_still_a_result() -> None:
    provider = FakeProvider({IP2: found(IP2)})
    outcome = run(provider, {"dns": dns(IP1, IP2)})
    assert outcome.status == "ok" and outcome.data["complete"] is True  # "unknown" is an answer


def test_a_failed_address_makes_the_result_incomplete_but_keeps_the_rest() -> None:
    provider = FakeProvider({IP1: found(), IP2: PortsLookup("error", "http_500")})
    outcome = run(provider, {"dns": dns(IP1, IP2)})
    assert outcome.status == "ok" and outcome.data["complete"] is False
    failed = outcome.data["addresses"][1]
    assert (failed["status"], failed["reason"], failed["facts"]) == ("error", "http_500", None)
    assert provider.calls == [IP1, IP2]  # a server error does not stop the others


def test_when_nothing_could_be_asked_the_failure_shows_instead_of_no_data() -> None:
    errors = run(FakeProvider(default=PortsLookup("error", "http_500")), {"dns": dns(IP1, IP2)})
    assert (errors.status, errors.reason_code) == ("error", "http_500")

    mixed = FakeProvider(
        {IP1: PortsLookup("no_data", "no_information")}, PortsLookup("error", "http_503")
    )
    outcome = run(mixed, {"dns": dns(IP1, IP2)})
    assert (outcome.status, outcome.reason_code) == ("error", "http_503")  # not "no data"

    quota = FakeProvider(
        {IP1: PortsLookup("no_data", "no_information")}, PortsLookup("unavailable", "rate_limited")
    )
    assert run(quota, {"dns": dns(IP1, IP2)}).status == "unavailable"


@pytest.mark.parametrize("reason", ["invalid_key", "membership_required", "rate_limited"])
def test_a_provider_wide_failure_stops_further_lookups(reason: str) -> None:
    provider = FakeProvider(default=PortsLookup("unavailable", reason))
    outcome = run(provider, {"dns": dns(IP1, IP2, IP3)})

    assert provider.calls == [IP1]  # the others would fail the same way
    assert (outcome.status, outcome.reason_code) == ("unavailable", reason)
    skipped = outcome.data["addresses"][1:]
    assert [(e["status"], e["reason"]) for e in skipped] == [("unavailable", "not_asked")] * 2


def test_timeouts_stop_further_lookups_too() -> None:
    provider = FakeProvider(default=PortsLookup("error", "timeout"))
    outcome = run(provider, {"dns": dns(IP1, IP2, IP3)})
    assert provider.calls == [IP1]
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")


def test_only_the_first_addresses_are_asked() -> None:
    addresses = [f"93.184.216.{n}" for n in range(1, 7)]
    provider = FakeProvider()
    outcome = run(provider, {"dns": dns(*addresses)})
    assert provider.calls == addresses[:MAX_ADDRESSES] and MAX_ADDRESSES == 4
    assert (outcome.data["truncated"], outcome.data["addresses_total"]) == (True, 6)
    assert len(outcome.data["addresses"]) == MAX_ADDRESSES


# ------------------------------------------------------------------------------ attribution


@pytest.mark.parametrize(
    ("fields", "network", "hostname", "expected", "basis"),
    [
        ({}, None, HOST, "ip_only", []),
        ({"hostnames": (HOST,)}, None, HOST, "hostname_supported", ["hostname_listed"]),
        (
            {"hostnames": ("WWW.Example.COM",)},
            None,
            HOST,
            "hostname_supported",
            ["hostname_listed"],
        ),
        ({"hostnames": ("other.example.com",)}, None, HOST, "ip_only", []),
        ({}, CLOUDFLARE, HOST, "shared_infrastructure", ["network:Cloudflare"]),
        ({"tags": ("cdn",)}, None, HOST, "shared_infrastructure", ["tag:cdn"]),
        ({"tags": ("CDN", "cloud")}, None, HOST, "shared_infrastructure", ["tag:cdn"]),
        ({"org": "Cloudflare, Inc."}, None, HOST, "shared_infrastructure", ["org:cloudflare"]),
        ({"isp": "Akamai Technologies"}, None, HOST, "shared_infrastructure", ["org:akamai"]),
        (
            {"hostnames": tuple(f"h{n}.example.net" for n in range(6))},
            None,
            HOST,
            "shared_infrastructure",
            ["many_hostnames"],
        ),
        (
            {"hostnames": tuple(f"h{n}.example.net" for n in range(5))},
            None,
            HOST,
            "ip_only",  # five names are not "many"
            [],
        ),
        # A cloud VM is dedicated to someone, not a shared edge: no shared infrastructure.
        ({"tags": ("cloud", "eol-product")}, AWS, HOST, "ip_only", []),
        # Several reasons are all reported; shared outranks "this host name is listed".
        (
            {"tags": ("cdn",), "hostnames": (HOST,), "org": "Fastly"},
            CLOUDFLARE,
            HOST,
            "shared_infrastructure",
            ["network:Cloudflare", "tag:cdn", "org:fastly"],
        ),
        ({"hostnames": (HOST,)}, None, None, "ip_only", []),  # no host name to compare
    ],
)
def test_attribution_says_how_far_the_results_speak_for_the_host(
    fields: dict[str, Any],
    network: dict[str, Any] | None,
    hostname: str | None,
    expected: str,
    basis: list[str],
) -> None:
    assert attribute(facts(**fields), hostname, network) == (expected, basis)


def test_the_ip_checks_cdn_hint_marks_the_address_as_shared() -> None:
    previous = {"dns": dns(IP1), "ip": ip_outcome(located(IP1, CLOUDFLARE, 13335))}
    outcome = run(FakeProvider({IP1: found()}), previous)
    entry = outcome.data["addresses"][0]
    assert entry["attribution"] == "shared_infrastructure"
    assert entry["attribution_basis"] == ["network:Cloudflare"]
    assert entry["network"] == CLOUDFLARE


def test_without_the_ip_check_the_cname_chain_still_reveals_a_cdn() -> None:
    previous = {"dns": dns(IP1, cname="d111111abcdef8.cloudfront.net")}  # no "ip" outcome at all
    outcome = run(FakeProvider({IP1: found()}), previous)
    entry = outcome.data["addresses"][0]
    assert (entry["attribution"], entry["attribution_basis"]) == (
        "shared_infrastructure",
        ["network:Amazon CloudFront"],
    )


def test_a_failed_ip_check_does_not_get_in_the_way() -> None:
    previous = {"dns": dns(IP1), "ip": CheckOutcome("unavailable", "datasets_missing")}
    outcome = run(FakeProvider({IP1: found()}), previous)
    assert outcome.status == "ok" and outcome.data["addresses"][0]["attribution"] == "ip_only"


def test_the_as_number_from_the_ip_check_is_used_when_no_name_gives_a_hint() -> None:
    previous = {"dns": dns(IP1), "ip": ip_outcome(located(IP1, None, 13335))}  # Cloudflare's AS
    outcome = run(FakeProvider({IP1: found()}), previous)
    assert outcome.data["addresses"][0]["attribution"] == "shared_infrastructure"


def test_names_the_provider_lists_can_reveal_a_cdn_too() -> None:
    seen = found(hostnames=("something.fastly.net",))
    outcome = run(FakeProvider({IP1: seen}), {"dns": dns(IP1)})
    assert outcome.data["addresses"][0]["attribution"] == "shared_infrastructure"


# ------------------------------------------------------------------------------ the cache


def test_answers_are_remembered_so_a_rescan_asks_nobody() -> None:
    cache = FakeCache()
    first = FakeProvider({IP1: found(cves=("CVE-2021-23017",))})
    outcome = run(first, {"dns": dns(IP1, IP2)}, cache=cache)  # IP2: no data
    assert first.calls == [IP1, IP2]
    assert cache.puts == [("shodan", IP1, "ok"), ("shodan", IP2, "no_data")]

    cache.now = NOW + timedelta(hours=2)
    second = FakeProvider()
    again = run(second, {"dns": dns(IP1, IP2)}, cache=cache)
    assert second.calls == []
    entries = again.data["addresses"]
    assert [(e["status"], e["cached"]) for e in entries] == [("ok", True), ("no_data", True)]
    assert entries[0]["fetched_at"] == NOW.isoformat()  # when it was fetched, not when it was read
    assert entries[0]["facts"] == outcome.data["addresses"][0]["facts"]  # nothing lost on the way


def test_hosts_sharing_an_address_ask_the_provider_once_even_when_checked_together() -> None:
    """The first asks, the others wait for its answer in the cache (a paid, rate-limited call)."""

    class SlowProvider(FakeProvider):
        def lookup(self, ip: str) -> PortsLookup:
            time.sleep(0.05)  # long enough for every other thread to arrive meanwhile
            return super().lookup(ip)

    provider = SlowProvider({IP1: found()})
    cache = FakeCache()
    check = PortsCheck(provider_factory=lambda ctx: provider, clock=lambda: NOW)
    start = threading.Barrier(6)
    outcomes: list[CheckOutcome] = []

    def one_host(number: int) -> None:
        ctx = CheckContext(
            domain="example.com",
            hostname=f"h{number}.example.com",
            config={},
            http=HTTP,
            previous={"dns": dns(IP1)},
            cache=cache,
        )
        start.wait(timeout=10)
        outcomes.append(check.run(ctx))

    threads = [threading.Thread(target=one_host, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert provider.calls == [IP1]  # one call for six hosts
    flags = sorted(outcome.data["addresses"][0]["cached"] for outcome in outcomes)
    assert flags == [False, True, True, True, True, True]
    assert {outcome.status for outcome in outcomes} == {"ok"}


def test_errors_and_quota_problems_are_never_cached() -> None:
    cache = FakeCache()
    provider = FakeProvider(
        {IP1: PortsLookup("error", "http_500"), IP2: PortsLookup("unavailable", "rate_limited")}
    )
    run(provider, {"dns": dns(IP1, IP2)}, cache=cache)
    assert cache.puts == [] and cache.rows == {}


def test_an_old_entry_is_asked_again() -> None:
    cache = FakeCache()
    run(FakeProvider({IP1: found()}), {"dns": dns(IP1)}, cache=cache)
    cache.now = NOW + timedelta(hours=25)  # the default lifetime is 24 hours
    provider = FakeProvider({IP1: found()})
    run(provider, {"dns": dns(IP1)}, cache=cache)
    assert provider.calls == [IP1]


def test_the_lifetime_is_configurable() -> None:
    cache = FakeCache()
    previous = {"dns": dns(IP1)}
    run(FakeProvider({IP1: found()}), previous, cache=cache)
    cache.now = NOW + timedelta(hours=2)

    short = FakeProvider({IP1: found()})
    run(short, previous, config={"PORTS_CACHE_HOURS": 1}, cache=cache)
    assert short.calls == [IP1]

    cache.rows[("shodan", IP1)] = CachedAnswer("ok", facts().to_data(), NOW)  # back to 2 hours old
    long = FakeProvider({IP1: found()})
    run(long, previous, config={"PORTS_CACHE_HOURS": 48}, cache=cache)
    assert long.calls == []


def test_an_unreadable_entry_counts_as_a_miss() -> None:
    cache = FakeCache()
    cache.rows[("shodan", IP1)] = CachedAnswer("ok", {"nonsense": True}, NOW)
    provider = FakeProvider({IP1: found()})
    outcome = run(provider, {"dns": dns(IP1)}, cache=cache)
    assert provider.calls == [IP1] and outcome.status == "ok"
    assert cache.rows[("shodan", IP1)].payload["ports"] == [80, 443]  # repaired


def test_providers_do_not_share_cache_entries() -> None:
    cache = FakeCache()
    cache.rows[("internetdb", IP1)] = CachedAnswer(
        "ok", facts(provider="internetdb").to_data(), NOW
    )
    provider = FakeProvider({IP1: found()})  # a Shodan lookup
    run(provider, {"dns": dns(IP1)}, cache=cache)
    assert provider.calls == [IP1]


def test_the_check_works_without_a_cache() -> None:
    provider = FakeProvider({IP1: found()})
    assert run(provider, {"dns": dns(IP1)}, cache=None).status == "ok"


# ------------------------------------------------------------------------------ the real providers


def test_with_a_key_the_shodan_host_api_is_used_and_the_key_stays_out_of_the_result() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200, json={"ports": [443], "org": "Example Hosting", "vulns": ["CVE-2021-23017"]}
        )

    config = {"PORTS_PROVIDER": "auto", "SHODAN_API_KEY": KEY, "SHODAN_RATE_PER_SECOND": 1000}
    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config=config,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        previous={"dns": dns(IP1)},
    )
    outcome = PortsCheck().run(ctx)

    assert outcome.status == "ok" and outcome.source == "shodan"
    assert [request.url.host for request in seen] == ["api.shodan.io"]
    assert KEY not in json.dumps(outcome.data)


def test_the_keyless_internetdb_is_used_only_when_it_is_asked_for() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ports": [80, 443], "vulns": [], "tags": ["cloud"]})

    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config={"PORTS_PROVIDER": "internetdb", "INTERNETDB_RATE_PER_SECOND": 1000},
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        previous={"dns": dns(IP1)},
    )
    outcome = PortsCheck().run(ctx)

    assert outcome.status == "ok" and outcome.source == "internetdb"
    assert str(seen[0].url) == f"https://internetdb.shodan.io/{IP1}"


@pytest.mark.parametrize("config", [{}, {"PORTS_PROVIDER": "auto", "SHODAN_API_KEY": ""}])
def test_auto_without_a_key_is_off_and_sends_nothing(config: dict[str, Any]) -> None:
    """InternetDB's terms need the operator's decision, so `auto` never falls back to it."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ports": [80], "vulns": [], "tags": []})

    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config=config,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        previous={"dns": dns(IP1)},
    )
    outcome = PortsCheck().run(ctx)

    assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")
    assert seen == []  # not a single request left


def test_a_shodan_choice_without_a_key_is_reported_not_silently_downgraded() -> None:
    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config={"PORTS_PROVIDER": "shodan"},
        http=HTTP,
        previous={"dns": dns(IP1)},
    )
    outcome = PortsCheck().run(ctx)
    assert (outcome.status, outcome.reason_code) == ("unavailable", "missing_api_key")


def test_a_switched_off_check_says_so() -> None:
    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config={"PORTS_PROVIDER": "off"},
        http=HTTP,
        previous={"dns": dns(IP1)},
    )
    outcome = PortsCheck().run(ctx)
    assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")
