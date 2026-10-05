"""The registration check over recorded RDAP answers (real registries, 2026-10-05) and a mock
HTTPS transport. No network."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.checks.base import CachedAnswer, CheckContext, CheckOutcome
from app.checks.registration import (
    BOOTSTRAP_URL,
    MAX_LIST,
    SUPPLEMENTAL,
    RegistrationCheck,
    parse_bootstrap,
    parse_rdap,
    with_ages,
)
from app.service.discovery.psl import registrable_domain
from runner.egress import EgressHTTPClient

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rdap"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


BOOTSTRAP = fixture("iana_bootstrap_subset.json")
RESPONSES = {
    "example.com": fixture("verisign_example_com.json"),
    "github.com": fixture("verisign_github_com.json"),
    "admin.ch": fixture("nic_ch_admin_ch.json"),
    "denic.de": fixture("denic_denic_de.json"),
}


class Cache:
    """An in-memory ``CacheStore`` with a movable clock."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], CachedAnswer] = {}
        self.now = NOW

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None:
        row = self.rows.get((provider, key))
        return None if row is None or row.fetched_at < self.now - max_age else row

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None:
        self.rows[(provider, key)] = CachedAnswer(status, payload, self.now)


class Registry:
    """A mock web: IANA's bootstrap and the registries' RDAP servers; remembers every request."""

    def __init__(self, domains: dict[str, Any] | None = None) -> None:
        self.domains = RESPONSES if domains is None else domains
        self.requests: list[tuple[str, str]] = []  # (host, path)
        self.bootstrap: Callable[[], httpx.Response] = lambda: httpx.Response(200, json=BOOTSTRAP)
        self.override: Callable[[httpx.Request], httpx.Response | None] = lambda request: None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host, path = request.headers["host"], request.url.path
        self.requests.append((host, path))
        custom = self.override(request)
        if custom is not None:
            return custom
        if host == "data.iana.org":
            return self.bootstrap()
        name = path.rsplit("/domain/", 1)[-1]
        if "/domain/" in path and name in self.domains:
            return httpx.Response(
                200, json=self.domains[name], headers={"content-type": "application/rdap+json"}
            )
        return httpx.Response(404, headers={"content-type": "application/rdap+json"})

    def rdap_requests(self) -> list[tuple[str, str]]:
        return [r for r in self.requests if r[0] != "data.iana.org"]


def client_factory(
    handler: Callable[[httpx.Request], httpx.Response], ip: str = "93.184.216.34"
) -> Any:
    def factory(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            custom_transport=httpx.MockTransport(handler), resolver_fn=lambda name: [ip]
        )

    return factory


def run(
    domain: str,
    web: Callable[[httpx.Request], httpx.Response],
    *,
    cache: Cache | None = None,
    config: dict[str, Any] | None = None,
    clock: datetime = NOW,
    ip: str = "93.184.216.34",
) -> CheckOutcome:
    check = RegistrationCheck(
        client_factory=client_factory(web, ip),
        name_resolver=lambda config, name: [ip],
        clock=lambda: clock,
    )
    ctx = CheckContext(
        domain=domain, hostname=None, config=config or {}, http=httpx.Client(), cache=cache
    )
    return check.run(ctx)


# ------------------------------------------------------------------------------ real answers


def test_a_gtld_registry_answer_gives_registrar_dates_locks_and_dnssec() -> None:
    web = Registry()
    outcome = run("example.com", web)

    assert outcome.status == "ok" and outcome.source == "rdap:rdap.verisign.com"
    data = outcome.data
    assert (
        data["server"] == "https://rdap.verisign.com/com/v1/" and data["queried"] == "example.com"
    )
    assert data["registrar"] == {
        "name": "RESERVED-Internet Assigned Numbers Authority",
        "iana_id": "376",
    }
    assert data["created"] == "1995-08-14T04:00:00+00:00"
    assert data["expires"] == "2027-08-13T04:00:00+00:00"
    assert data["days_to_expiry"] == (datetime(2027, 8, 13, 4, tzinfo=UTC) - NOW).days
    assert data["age_days"] == (NOW - datetime(1995, 8, 14, 4, tzinfo=UTC)).days
    assert data["statuses"] == [
        "client delete prohibited",
        "client transfer prohibited",
        "client update prohibited",
    ]
    assert data["transfer_locked"] is True and data["dnssec"] is True
    assert data["dates_published"] is True
    assert data["nameservers"] and all(name == name.lower() for name in data["nameservers"])
    assert (data["cached"], data["fetched_at"]) == (False, NOW.isoformat())
    assert web.rdap_requests() == [("rdap.verisign.com", "/com/v1/domain/example.com")]
    json.dumps(data)  # storable


def test_a_domain_without_dnssec_is_stated_as_such() -> None:
    outcome = run("github.com", Registry())
    assert outcome.data["dnssec"] is False
    assert outcome.data["registrar"]["name"] == "MarkMonitor Inc."
    assert len(outcome.data["nameservers"]) == 8


def test_the_swiss_registry_publishes_no_dates_and_the_check_does_not_invent_any() -> None:
    web = Registry()
    outcome = run("admin.ch", web)  # .ch is not in IANA's list: the supplemental table is used

    assert outcome.status == "ok" and outcome.source == "rdap:rdap.nic.ch"
    data = outcome.data
    assert (data["created"], data["expires"], data["changed"]) == (None, None, None)
    assert (data["days_to_expiry"], data["age_days"], data["dates_published"]) == (
        None,
        None,
        False,
    )
    assert data["registrar"] == {"name": "cyon AG", "iana_id": None}  # the jCard has an org only
    assert data["statuses"] == ["active"] and data["transfer_locked"] is False
    assert data["dnssec"] is False and len(data["nameservers"]) == 5
    assert ("rdap.nic.ch", "/domain/admin.ch") in web.requests


def test_the_german_registry_signals_dnssec_by_its_keys_and_names_no_registrar() -> None:
    outcome = run("denic.de", Registry())
    data = outcome.data
    assert data["dnssec"] is True  # keyData without a delegationSigned flag
    assert data["registrar"] is None and data["changed"] is not None and data["created"] is None
    assert data["nameservers"] == ["ns1.denic.de", "ns2.denic.de", "ns3.denic.de", "ns4.denic.net"]


def test_the_registry_of_a_subdomain_scope_is_asked_about_its_registrable_name() -> None:
    web = Registry()
    outcome = run("shop.eu.example.com", web)
    assert outcome.data["domain"] == "shop.eu.example.com"
    assert outcome.data["queried"] == "example.com"
    assert web.rdap_requests() == [("rdap.verisign.com", "/com/v1/domain/example.com")]


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("shop.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("foo.blogspot.com", "blogspot.com"),  # a private suffix is not a registry
        ("admin.ch", "admin.ch"),
        ("com", None),
        ("co.uk", None),
    ],
)
def test_the_registrable_domain(domain: str, expected: str | None) -> None:
    assert registrable_domain(domain) == expected


# ------------------------------------------------------------------------------ typed failures


def test_a_tld_without_rdap_is_no_data_and_says_why() -> None:
    web = Registry()
    outcome = run("example.zz", web)
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_rdap_service")
    assert web.rdap_requests() == []  # nobody was asked


def test_an_unregistered_domain_is_no_data() -> None:
    outcome = run("no-such-domain-0b6f1c.com", Registry())
    assert (outcome.status, outcome.reason_code) == ("no_data", "not_found")
    assert outcome.data["server"] == "https://rdap.verisign.com/com/v1/"


@pytest.mark.parametrize(
    ("response", "status", "reason"),
    [
        (httpx.Response(429), "unavailable", "rate_limited"),
        (httpx.Response(403), "unavailable", "not_allowed"),
        (httpx.Response(401), "unavailable", "not_allowed"),
        (httpx.Response(500), "error", "http_500"),
        (httpx.Response(503), "error", "http_503"),
        (httpx.Response(200, text="<html>not json</html>"), "error", "invalid_response"),
        (httpx.Response(200, json=["a", "list"]), "error", "invalid_response"),
        (
            httpx.Response(200, json={"objectClassName": "error", "errorCode": 400}),
            "error",
            "invalid_response",
        ),
    ],
)
def test_registry_failures_are_typed(response: httpx.Response, status: str, reason: str) -> None:
    web = Registry()
    web.override = lambda request: response if request.headers["host"] != "data.iana.org" else None
    outcome = run("example.com", web)
    assert (outcome.status, outcome.reason_code) == (status, reason)
    assert outcome.data["queried"] == "example.com"


def test_a_registry_timeout_is_an_error() -> None:
    def slow(request: httpx.Request) -> httpx.Response | None:
        if request.headers["host"] != "data.iana.org":
            raise httpx.ReadTimeout("slow", request=request)
        return None

    web = Registry()
    web.override = slow
    outcome = run("example.com", web)
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")


def test_a_registry_that_resolves_to_a_private_address_is_never_contacted() -> None:
    web = Registry()
    outcome = run("example.com", web, ip="10.0.0.5")
    assert (outcome.status, outcome.reason_code) == ("error", "bootstrap_failed")
    assert web.requests == []  # blocked before any connection, including for the bootstrap


@pytest.mark.parametrize(
    "broken",
    [
        lambda: httpx.Response(500),
        lambda: httpx.Response(200, text="not json"),
        lambda: httpx.Response(200, json={"services": "nope"}),
        lambda: httpx.Response(200, json={"services": []}),
    ],
)
def test_an_unreadable_bootstrap_is_an_error_but_does_not_stop_the_supplemental_tlds(
    broken: Callable[[], httpx.Response],
) -> None:
    web = Registry()
    web.bootstrap = broken
    outcome = run("example.com", web)
    assert (outcome.status, outcome.reason_code) == ("error", "bootstrap_failed")
    assert run("admin.ch", web).status == "ok"  # .ch is known without the bootstrap


def test_an_oversized_bootstrap_is_not_trusted() -> None:
    web = Registry()
    web.bootstrap = lambda: httpx.Response(200, content=b"x" * (600 * 1024))
    outcome = run("example.com", web)
    assert (outcome.status, outcome.reason_code) == ("error", "bootstrap_failed")


def test_a_switched_off_lookup_asks_nobody() -> None:
    web = Registry()
    for lookups in ([], ["hibp", "hsts_preload"]):
        outcome = run("example.com", web, config={"EXTERNAL_DOMAIN_LOOKUPS": lookups})
        assert (outcome.status, outcome.reason_code) == ("unavailable", "disabled")
    assert web.requests == []
    assert run("example.com", web, config={"EXTERNAL_DOMAIN_LOOKUPS": ["rdap"]}).status == "ok"


# ------------------------------------------------------------------------------ the cache


def test_the_answer_and_the_bootstrap_are_cached_and_ages_are_worked_out_again() -> None:
    cache = Cache()
    first = Registry()
    run("example.com", first, cache=cache)
    assert [h for h, _ in first.requests] == ["data.iana.org", "rdap.verisign.com"]

    cache.now = NOW + timedelta(hours=3)
    later = Registry()  # a web that would answer, but must not be asked
    again = run("example.com", later, cache=cache, clock=NOW + timedelta(days=10))
    assert later.requests == []
    assert again.data["cached"] is True and again.data["fetched_at"] == NOW.isoformat()
    first_days = run("example.com", Registry()).data["days_to_expiry"]
    assert again.data["days_to_expiry"] == first_days - 10  # not the stale number
    assert again.source == "rdap:rdap.verisign.com"


def test_one_bootstrap_fetch_serves_every_domain() -> None:
    cache = Cache()
    web = Registry()
    run("example.com", web, cache=cache)
    run("github.com", web, cache=cache)
    run("admin.ch", web, cache=cache)
    assert [host for host, _ in web.requests].count("data.iana.org") == 1


def test_failures_are_never_cached() -> None:
    cache = Cache()
    web = Registry()
    web.override = lambda request: (
        httpx.Response(500) if request.headers["host"] != "data.iana.org" else None
    )
    run("example.com", web, cache=cache)
    assert ("rdap", "example.com") not in cache.rows  # but the bootstrap was worth keeping
    assert ("iana-rdap", "dns.json") in cache.rows


def test_an_old_cache_entry_is_asked_again() -> None:
    cache = Cache()
    run("example.com", Registry(), cache=cache)
    cache.now = NOW + timedelta(hours=25)
    web = Registry()
    run("example.com", web, cache=cache)
    assert any(host == "rdap.verisign.com" for host, _ in web.requests)


# ------------------------------------------------------------------------------ the parsers


def test_registrant_and_contact_entities_are_never_kept() -> None:
    body = {
        "objectClassName": "domain",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Jane Doe"], ["email", {}, "text", "jane@example.org"]],
                ],
            },
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Example Registrar"],
                        ["tel", {}, "uri", "tel:+41000000"],
                        ["adr", {}, "text", ["", "", "1 Main St", "Bern"]],
                    ],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [["email", {}, "text", "abuse@r.example"]]],
                    }
                ],
            },
            {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Tech Person"]]]},
        ],
    }
    facts = parse_rdap(body)
    assert facts["registrar"] == {"name": "Example Registrar", "iana_id": None}
    dumped = json.dumps(facts)
    for private in ("Jane", "jane@", "+41000000", "Main St", "abuse@", "Tech Person"):
        assert private not in dumped


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2027-08-13T04:00:00Z", "2027-08-13T04:00:00+00:00"),
        ("2025-10-29T03:51:11.009091Z", "2025-10-29T03:51:11.009091+00:00"),
        ("2027-08-13T06:00:00+02:00", "2027-08-13T04:00:00+00:00"),
        ("2027-08-13T04:00:00", "2027-08-13T04:00:00+00:00"),  # no zone: UTC
        ("yesterday", None),
        ("", None),
        (20270813, None),
        (None, None),
    ],
)
def test_dates_are_normalised_to_utc_and_odd_ones_ignored(
    value: object, expected: str | None
) -> None:
    facts = parse_rdap({"events": [{"eventAction": "expiration", "eventDate": value}]})
    assert facts["expires"] == expected


def test_odd_shapes_never_crash_the_parser_and_lists_are_bounded() -> None:
    facts = parse_rdap(
        {
            "events": "no",
            "status": ["Active", 7, "", "ACTIVE", *[f"s{n}" for n in range(50)]],
            "nameservers": [{"ldhName": f"NS{n}.Example.COM."} for n in range(50)]
            + [{"x": 1}, "y"],
            "entities": {"not": "a list"},
            "secureDNS": "no",
        }
    )
    assert facts["registrar"] is None and facts["dnssec"] is None
    assert len(facts["statuses"]) == MAX_LIST and len(facts["nameservers"]) == MAX_LIST
    assert facts["statuses"][0] == "active"  # lower-cased and de-duplicated
    assert all(name == name.lower() and not name.endswith(".") for name in facts["nameservers"])
    assert parse_rdap({}) == {
        "registrar": None,
        "created": None,
        "expires": None,
        "changed": None,
        "statuses": [],
        "transfer_locked": False,
        "nameservers": [],
        "dnssec": None,
    }


@pytest.mark.parametrize(
    ("secure", "expected"),
    [
        ({"delegationSigned": True}, True),
        ({"delegationSigned": False}, False),
        ({"dsData": [{"keyTag": 1}]}, True),
        ({"keyData": [{"algorithm": 8}]}, True),
        ({}, None),
        (None, None),
    ],
)
def test_dnssec_is_read_from_the_flag_or_the_keys(secure: object, expected: bool | None) -> None:
    assert parse_rdap({"secureDNS": secure})["dnssec"] is expected


def test_the_ages_are_worked_out_for_the_moment_asked() -> None:
    facts = parse_rdap(
        {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-10-05T12:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-10-04T12:00:00Z"},
            ]
        }
    )
    aged = with_ages(facts, NOW)
    assert (aged["days_to_expiry"], aged["age_days"]) == (
        -1,
        (NOW - datetime(2020, 10, 5, 12, tzinfo=UTC)).days,
    )
    assert with_ages(facts, NOW - timedelta(days=30))["days_to_expiry"] == 29


def test_the_bootstrap_keeps_only_https_servers_and_normalises_them() -> None:
    raw = {
        "services": [
            [["COM", "net"], ["https://rdap.example/com/v1"]],
            [["org"], ["http://insecure.example/", "https://rdap.example/org/"]],
            [["xx"], ["http://only-plain.example/"]],
            [["yy"], "not a list"],
            ["junk"],
            [[7, None], ["https://rdap.example/never/"]],
        ]
    }
    assert parse_bootstrap(raw) == {
        "com": "https://rdap.example/com/v1/",
        "net": "https://rdap.example/com/v1/",
        "org": "https://rdap.example/org/",
    }
    assert parse_bootstrap("nonsense") == {} and parse_bootstrap({"services": 3}) == {}
    assert parse_bootstrap(BOOTSTRAP)["com"] == "https://rdap.verisign.com/com/v1/"


def test_the_supplemental_servers_are_https_with_a_trailing_slash() -> None:
    assert all(url.startswith("https://") and url.endswith("/") for url in SUPPLEMENTAL.values())
    assert BOOTSTRAP_URL.startswith("https://data.iana.org/")
