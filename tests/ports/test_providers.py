"""The ports providers: parsing, typed failures, bounds, and that the key never leaks.

The InternetDB fixture is a real, recorded response (2026-10-04). The Shodan fixture follows
Shodan's documented response shape: it has NOT been recorded from a real response yet.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.service.ports import (
    InternetDbProvider,
    PortFacts,
    ShodanProvider,
    build_provider,
)
from app.service.ports.internetdb import parse_internetdb
from app.service.ports.models import MAX_SERVICES, MAX_VULNERABILITIES
from app.service.ports.shodan import parse_shodan_host
from app.service.ratelimit import RateLimiter

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ports"
KEY = "SECRET-KEY-0123456789"
IP = "93.184.216.34"


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


class CountingLimiter(RateLimiter):
    def __init__(self) -> None:
        super().__init__(1000.0)
        self.acquired = 0

    def acquire(self) -> float:
        self.acquired += 1
        return 0.0


def client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def internetdb(handler: Callable[[httpx.Request], httpx.Response]) -> InternetDbProvider:
    return InternetDbProvider(client(handler), CountingLimiter())


def shodan(handler: Callable[[httpx.Request], httpx.Response]) -> ShodanProvider:
    return ShodanProvider(client(handler), KEY, CountingLimiter())


# ------------------------------------------------------------------------------ InternetDB


def test_a_real_internetdb_answer_is_parsed_completely() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=fixture("internetdb_badssl.json"))

    limiter = CountingLimiter()
    result = InternetDbProvider(client(handler), limiter).lookup("104.154.89.105")

    assert result.status == "ok" and result.facts is not None
    facts = result.facts
    assert (facts.provider, facts.ip) == ("internetdb", "104.154.89.105")
    assert facts.ports == [80, 443, 1002, 1012]
    assert [service.transport for service in facts.services] == [None] * 4  # it does not say
    assert len(facts.vulnerabilities) == 12
    assert facts.vulnerabilities[0].id == "CVE-2017-20005"  # sorted
    assert all(v.cvss is None and v.summary is None for v in facts.vulnerabilities)  # no scores
    assert facts.tags == ("cloud", "eol-product") and "cpe:/a:f5:nginx:1.10.3" in facts.cpes
    assert "badssl.com" in facts.hostnames
    assert str(seen[0].url) == "https://internetdb.shodan.io/104.154.89.105"
    assert limiter.acquired == 1  # one call, one slot


def test_internetdb_failures_are_typed() -> None:
    cases: dict[str, Callable[[httpx.Request], httpx.Response]] = {
        "no_data/no_information": lambda r: httpx.Response(404, json={"detail": "none"}),
        "unavailable/rate_limited": lambda r: httpx.Response(429),
        "error/http_500": lambda r: httpx.Response(500),
        "error/invalid_response": lambda r: httpx.Response(200, text="<html>"),
    }
    for expected, handler in cases.items():
        result = internetdb(handler).lookup(IP)
        assert f"{result.status}/{result.reason}" == expected and result.facts is None

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    assert internetdb(timeout).lookup(IP).reason == "timeout"
    assert internetdb(refused).lookup(IP).reason == "connection_failed"
    assert (
        internetdb(lambda r: httpx.Response(200, json=[1, 2])).lookup(IP).reason
        == "invalid_response"
    )


def test_internetdb_data_is_bounded_and_cleaned() -> None:
    payload = {
        "ports": [*range(2, 400), 0, 70000, "80", True, 1.5],  # True is not port 1
        "vulns": ["CVE-2020-0001", "cve-2020-0002", "CVE-20-1", "javascript:alert(1)"]
        + [f"CVE-2020-{n:05}" for n in range(1, 500)],
        "hostnames": ["ok.example.com", "bad\x00name\n.example.com", 42, "   "],
        "tags": "not a list",
        "cpes": None,
    }
    facts = parse_internetdb(IP, payload)
    assert facts is not None
    assert len(facts.services) == MAX_SERVICES and facts.ports[0] == 2
    assert len(facts.vulnerabilities) == MAX_VULNERABILITIES
    assert all(v.id.startswith("CVE-") and v.id != "CVE-20-1" for v in facts.vulnerabilities)
    assert facts.hostnames == ("ok.example.com", "badname.example.com")  # control characters gone
    assert facts.tags == () and facts.cpes == ()
    assert parse_internetdb(IP, "nonsense") is None


# ------------------------------------------------------------------------------ Shodan


def test_a_shodan_host_answer_is_parsed_with_products_versions_and_cve_details() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=fixture("shodan_host_documented_shape.json"))

    result = shodan(handler).lookup(IP)
    assert result.status == "ok" and result.facts is not None
    facts = result.facts

    assert facts.provider == "shodan"
    assert facts.ports == [22, 53, 80, 443, 8080]
    by_port = {service.port: service for service in facts.services}
    assert (by_port[22].product, by_port[22].version) == ("OpenSSH", "7.4")
    assert by_port[22].cpe == ("cpe:/a:openbsd:openssh:7.4",)
    assert by_port[80].cpe == ("cpe:/a:igor_sysoev:nginx:1.10.3",)  # a plain string works too
    assert (by_port[53].transport, by_port[8080].product) == ("udp", None)

    cves = {vuln.id: vuln for vuln in facts.vulnerabilities}
    assert sorted(cves) == [
        "CVE-2018-1000999",
        "CVE-2019-9511",
        "CVE-2021-23017",
    ]  # "not-a-cve" dropped
    assert (cves["CVE-2021-23017"].cvss, cves["CVE-2021-23017"].verified) == (7.7, False)
    assert cves["CVE-2021-23017"].summary == "A security issue in nginx resolver was identified."
    assert cves["CVE-2019-9511"].verified is True  # the banner's detail enriched the top-level id
    assert cves["CVE-2018-1000999"].cvss is None  # listed without details

    assert (facts.org, facts.isp, facts.asn, facts.os) == (
        "Example Hosting Inc.",
        "Example Hosting Inc.",
        "AS64496",
        "Linux",
    )
    assert facts.hostnames == ("example.org", "www.example.org") and facts.tags == ("cloud",)
    assert facts.last_update == "2026-09-28T04:11:23.123456"
    assert not any(
        "data" in service.to_data() for service in facts.services
    )  # banners are not kept

    request = seen[0]
    assert request.url.path == f"/shodan/host/{IP}" and request.url.params["key"] == KEY
    assert "authorization" not in request.headers


def test_shodan_failures_are_typed_and_never_contain_the_key() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"slow {request.url}", request=request)  # the text has the URL!

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    cases: list[tuple[str, Callable[[httpx.Request], httpx.Response]]] = [
        ("no_data/no_information", lambda r: httpx.Response(404, json={"error": "No info"})),
        ("unavailable/invalid_key", lambda r: httpx.Response(401, json={"error": "Invalid"})),
        ("unavailable/invalid_key", lambda r: httpx.Response(403)),
        ("unavailable/membership_required", lambda r: httpx.Response(402)),
        ("unavailable/rate_limited", lambda r: httpx.Response(429)),
        ("error/http_503", lambda r: httpx.Response(503)),
        ("error/invalid_response", lambda r: httpx.Response(200, text="not json")),
        ("error/invalid_response", lambda r: httpx.Response(200, json={"error": "No information"})),
        ("error/timeout", timeout),
        ("error/connection_failed", refused),
    ]
    for expected, handler in cases:
        result = shodan(handler).lookup(IP)
        assert f"{result.status}/{result.reason}" == expected, expected
        assert result.facts is None and KEY not in repr(result)  # nothing of the URL is carried


def test_odd_shodan_shapes_never_crash_the_parser() -> None:
    payload = {
        "ports": [80, "x", None, 99999],
        "vulns": {"CVE-2020-1111": {"cvss": "high", "verified": "yes"}, "CVE-2020-2222": None},
        "data": [
            "not a banner",
            {"transport": "tcp"},  # no port
            {"port": True},
            {"port": 80, "cpe": 5, "vulns": ["CVE-2020-3333", 7]},
            {"port": 8081, "product": "x" * 1000},
        ],
        "hostnames": {"a": "b"},
        "asn": 64500,
        "org": "O" * 500,
    }
    facts = parse_shodan_host(IP, payload)
    assert facts is not None
    assert facts.ports == [80, 8081]
    assert [v.id for v in facts.vulnerabilities] == [
        "CVE-2020-1111",
        "CVE-2020-2222",
        "CVE-2020-3333",
    ]
    assert all(v.cvss is None and v.verified is None for v in facts.vulnerabilities)
    assert len(facts.services[1].product or "") == 100 and len(facts.org or "") == 100
    assert facts.hostnames == () and facts.asn is None
    assert parse_shodan_host(IP, []) is None


def test_shodan_cves_come_highest_score_first_and_the_cap_keeps_the_worst() -> None:
    scored = {f"CVE-2020-{n:04}": {"cvss": n / 30} for n in range(1, 301)}  # 0.03 ... 10.0
    payload = {"vulns": [*scored, "CVE-2019-9999"], "data": [{"port": 80, "vulns": scored}]}
    facts = parse_shodan_host(IP, payload)

    assert facts is not None and len(facts.vulnerabilities) == MAX_VULNERABILITIES
    scores = [vuln.cvss or 0.0 for vuln in facts.vulnerabilities]
    assert scores == sorted(scores, reverse=True)
    assert facts.vulnerabilities[0].id == "CVE-2020-0300"  # the highest score
    assert "CVE-2019-9999" not in {vuln.id for vuln in facts.vulnerabilities}  # unscored: cut first
    assert facts.vulnerabilities[-1].cvss == pytest.approx(101 / 30)  # the lowest score kept


@pytest.mark.parametrize("bad", [99, -1, 10.5, float("nan"), float("inf"), True, "7.5", None, [7]])
def test_a_cvss_score_outside_zero_to_ten_is_not_a_score(bad: object) -> None:
    facts = parse_shodan_host(IP, {"vulns": {"CVE-2020-4444": {"cvss": bad}}})
    assert facts is not None
    assert [(v.id, v.cvss) for v in facts.vulnerabilities] == [("CVE-2020-4444", None)]


@pytest.mark.parametrize("good", [0, 0.0, 7, 7.5, 10, 10.0])
def test_scores_from_zero_to_ten_are_kept(good: float) -> None:
    facts = parse_shodan_host(IP, {"vulns": {"CVE-2020-4444": {"cvss": good}}})
    assert facts is not None and facts.vulnerabilities[0].cvss == float(good)


def test_the_facts_survive_a_round_trip_through_the_cache_form() -> None:
    original = parse_shodan_host(IP, fixture("shodan_host_documented_shape.json"))
    assert original is not None
    assert PortFacts.from_data(json.loads(json.dumps(original.to_data()))) == original
    real = parse_internetdb("104.154.89.105", fixture("internetdb_badssl.json"))
    assert real is not None and PortFacts.from_data(real.to_data()) == real


# ------------------------------------------------------------------------------ choosing a provider


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({}, "disabled"),  # no key: InternetDB's terms need a decision, so it is not used
        ({"PORTS_PROVIDER": "auto", "SHODAN_API_KEY": KEY}, "shodan"),
        ({"PORTS_PROVIDER": "auto", "SHODAN_API_KEY": ""}, "disabled"),  # never a silent fallback
        ({"PORTS_PROVIDER": "internetdb", "SHODAN_API_KEY": ""}, "internetdb"),  # asked for
        ({"PORTS_PROVIDER": "internetdb", "SHODAN_API_KEY": KEY}, "internetdb"),  # explicit wins
        ({"PORTS_PROVIDER": "shodan", "SHODAN_API_KEY": KEY}, "shodan"),
        ({"PORTS_PROVIDER": "shodan", "SHODAN_API_KEY": ""}, "missing_api_key"),
        ({"PORTS_PROVIDER": "off", "SHODAN_API_KEY": KEY}, "disabled"),
    ],
)
def test_the_provider_follows_the_configuration(config: dict[str, Any], expected: str) -> None:
    with httpx.Client() as http:
        chosen = build_provider(config, http)
    assert (chosen if isinstance(chosen, str) else chosen.name) == expected
