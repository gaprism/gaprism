"""The name-server and CAA check over scripted resolver answers (real dnspython objects)."""

from __future__ import annotations

from typing import Any

import dns.message
import dns.resolver
import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import ResolverLike
from app.checks.domain_dns import MAX_RECORDS, MAX_SERVERS, DomainDnsCheck, caa_summary
from tests.checks.test_dns_check import CONFIG, TIMEOUT, ScriptedResolver, answer, rr

ZONE = "example.com"


def ns_records(zone: str, *hosts: str) -> dns.resolver.Answer:
    return answer(zone, "NS", *(rr(zone, 3600, "NS", f"{host}.") for host in hosts))


def addresses(host: str, *ips: str) -> dict[tuple[str, str], Any]:
    v4 = [ip for ip in ips if ":" not in ip]
    v6 = [ip for ip in ips if ":" in ip]
    script: dict[tuple[str, str], Any] = {}
    if v4:
        script[(host, "A")] = answer(host, "A", *(rr(host, 300, "A", ip) for ip in v4))
    if v6:
        script[(host, "AAAA")] = answer(host, "AAAA", *(rr(host, 300, "AAAA", ip) for ip in v6))
    return script


def caa(name: str, *values: str) -> dns.resolver.Answer:
    return answer(name, "CAA", *(rr(name, 3600, "CAA", value) for value in values))


def run(
    script: dict[tuple[str, str], Any], domain: str = ZONE
) -> tuple[CheckOutcome, ScriptedResolver]:
    resolver = ScriptedResolver(script)

    def factory(_config: Any) -> ResolverLike:
        return resolver

    check = DomainDnsCheck(resolver_factory=factory)
    ctx = CheckContext(domain=domain, hostname=None, config=CONFIG, http=httpx.Client())
    return check.run(ctx), resolver


def healthy() -> dict[tuple[str, str], Any]:
    return {
        (ZONE, "NS"): ns_records(
            ZONE,
            "ns1.provider-a.net",
            "ns2.provider-a.net",
            "ns1.provider-b.org",
            "ns2.provider-b.org",
        ),
        **addresses("ns1.provider-a.net", "198.51.100.1", "2001:db8:a::1"),
        **addresses("ns2.provider-a.net", "198.51.101.1"),
        **addresses("ns1.provider-b.org", "203.0.113.7"),
        **addresses("ns2.provider-b.org", "203.0.114.7"),
        (ZONE, "CAA"): caa(
            ZONE, '0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:ca@example.com"'
        ),
    }


# ------------------------------------------------------------------------------ name servers


def test_a_well_spread_set_of_name_servers_has_no_problems() -> None:
    outcome, _ = run(healthy())
    assert (outcome.status, outcome.source) == ("ok", "dns:1.1.1.1,8.8.8.8")
    ns = outcome.data["ns"]
    assert ns["found"] is True and ns["count"] == 4 and ns["problems"] == []
    assert ns["single_operator"] is False
    assert ns["operators"] == ["provider-a.net", "provider-b.org"]
    assert ns["networks"] == [
        "198.51.100.0/24",
        "198.51.101.0/24",
        "2001:db8:a::/48",
        "203.0.113.0/24",
        "203.0.114.0/24",
    ]
    first = ns["servers"][0]
    assert first["host"] == "ns1.provider-a.net" and first["operator"] == "provider-a.net"
    assert first["addresses"] == ["198.51.100.1", "2001:db8:a::1"]


def test_operators_are_the_registered_domains_of_the_server_names() -> None:
    script = {
        (ZONE, "NS"): ns_records(
            ZONE, "dns1.p08.nsone.net", "ns-1283.awsdns-32.org", "ns-1707.awsdns-21.co.uk"
        ),
        **addresses("dns1.p08.nsone.net", "198.51.100.1"),
        **addresses("ns-1283.awsdns-32.org", "203.0.113.1"),
        **addresses("ns-1707.awsdns-21.co.uk", "192.0.2.1"),
    }
    ns = run(script)[0].data["ns"]
    assert ns["operators"] == ["awsdns-21.co.uk", "awsdns-32.org", "nsone.net"]


@pytest.mark.parametrize(
    ("hosts", "ips", "problems", "single_operator"),
    [
        # one operator is a note: the big DNS providers are redundant by design
        (["ns1.example.com", "ns2.example.com"], ["198.51.100.1", "203.0.113.1"], [], True),
        (["ns1.a.net", "ns2.b.org"], ["198.51.100.1", "198.51.100.200"], ["single_network"], False),
        (["ns1.a.net"], ["198.51.100.1"], ["too_few"], False),
        (
            ["ns1.example.com", "ns2.example.com"],
            ["198.51.100.1", "198.51.100.2"],
            ["single_network"],
            True,
        ),
    ],
)
def test_single_points_of_failure_are_problems_and_one_operator_is_a_note(
    hosts: list[str], ips: list[str], problems: list[str], single_operator: bool
) -> None:
    script: dict[tuple[str, str], Any] = {(ZONE, "NS"): ns_records(ZONE, *hosts)}
    for host, ip in zip(hosts, ips, strict=False):
        script.update(addresses(host, ip))
    ns = run(script)[0].data["ns"]
    assert ns["problems"] == problems and ns["single_operator"] is single_operator


def test_a_server_without_an_address_is_flagged() -> None:
    script = {
        (ZONE, "NS"): ns_records(ZONE, "ns1.a.net", "ns2.b.org"),
        **addresses("ns1.a.net", "198.51.100.1"),
    }
    ns = run(script)[0].data["ns"]
    assert "unresolvable" in ns["problems"]
    assert ns["servers"][1]["addresses"] == []


def test_the_number_of_servers_and_addresses_looked_up_is_bounded() -> None:
    hosts = [f"ns{n}.provider{n}.net" for n in range(20)]
    script: dict[tuple[str, str], Any] = {(ZONE, "NS"): ns_records(ZONE, *hosts)}
    for host in hosts:
        script.update(addresses(host, "198.51.100.1"))
    outcome, resolver = run(script)
    assert outcome.data["ns"]["count"] == 20 and len(outcome.data["ns"]["servers"]) == MAX_SERVERS
    assert len([c for c in resolver.calls if c[1] == "A"]) == MAX_SERVERS


def test_a_subdomain_scope_asks_the_zone_for_its_name_servers() -> None:
    script = healthy()
    outcome, resolver = run(script, "shop.eu.example.com")
    assert outcome.data["zone"] == ZONE and outcome.data["ns"]["count"] == 4
    assert (ZONE, "NS") in resolver.calls and ("shop.eu.example.com", "NS") not in resolver.calls


def test_no_name_servers_is_stated_not_hidden() -> None:
    outcome, _ = run({})
    assert outcome.status == "ok" and outcome.data["ns"] == {"found": False}


# ------------------------------------------------------------------------------ CAA


def test_the_caa_records_are_summarised() -> None:
    caa_data = run(healthy())[0].data["caa"]
    assert caa_data["found"] is True and caa_data["at"] == ZONE
    assert caa_data["issuers"] == ["letsencrypt.org"]
    assert caa_data["issuewild"] == []  # ";" means nobody
    assert caa_data["iodef"] == ["mailto:ca@example.com"]
    assert caa_data["forbids_issuance"] is False
    assert {r["tag"] for r in caa_data["records"]} == {"issue", "issuewild", "iodef"}


def test_issue_semicolon_forbids_every_authority() -> None:
    script = healthy()
    script[(ZONE, "CAA")] = caa(ZONE, '0 issue ";"')
    data = run(script)[0].data["caa"]
    assert data["forbids_issuance"] is True and data["issuers"] == []


def test_authorities_are_normalised_and_parameters_dropped() -> None:
    summary = caa_summary(
        [
            {"flags": 0, "tag": "issue", "value": "DigiCert.com; account=1234"},
            {"flags": 0, "tag": "ISSUE", "value": "digicert.com"},
            {"flags": 128, "tag": "issuewild", "value": "letsencrypt.org"},
        ]
    )
    assert summary["issuers"] == ["digicert.com"] and summary["issuewild"] == ["letsencrypt.org"]


def test_no_caa_is_a_fact() -> None:
    script = healthy()
    del script[(ZONE, "CAA")]
    assert run(script)[0].data["caa"] == {"found": False}


def test_the_closest_name_with_caa_records_decides() -> None:
    script = healthy()
    del script[(ZONE, "CAA")]
    script[("shop.example.com", "CAA")] = caa("shop.example.com", '0 issue "ca-one.example"')
    script[(ZONE, "CAA")] = caa(ZONE, '0 issue "ca-two.example"')
    data = run(script, "www.shop.example.com")[0].data["caa"]
    assert data["at"] == "shop.example.com" and data["issuers"] == ["ca-one.example"]


def test_a_parent_name_is_used_when_the_scope_has_none() -> None:
    outcome, resolver = run(healthy(), "www.shop.example.com")
    caa_calls = [name for name, rdtype in resolver.calls if rdtype == "CAA"]
    assert caa_calls == ["www.shop.example.com", "shop.example.com", "example.com"]
    assert outcome.data["caa"]["at"] == ZONE


def test_an_error_on_the_way_up_makes_the_answer_unknown_not_a_guess() -> None:
    script = healthy()
    script[("shop.example.com", "CAA")] = TIMEOUT  # the closer name might have its own records
    data = run(script, "shop.example.com")[0].data["caa"]
    assert data == {"found": None, "error": "timeout"}


def test_caa_records_are_bounded() -> None:
    script = healthy()
    script[(ZONE, "CAA")] = caa(ZONE, *[f'0 issue "ca{n}.example"' for n in range(40)])
    data = run(script)[0].data["caa"]
    assert len(data["records"]) <= MAX_RECORDS


# ------------------------------------------------------------------------------ failures


def test_a_domain_that_does_not_exist_is_no_data() -> None:
    outcome, _ = run({(ZONE, "NS"): dns.resolver.NXDOMAIN()})
    assert (outcome.status, outcome.reason_code) == ("no_data", "nxdomain")


def test_a_dead_resolver_is_an_error() -> None:
    outcome, _ = run({(ZONE, "NS"): TIMEOUT, (ZONE, "CAA"): TIMEOUT})
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")


def test_one_failing_part_leaves_the_other_intact() -> None:
    script = healthy()
    script[(ZONE, "NS")] = dns.resolver.NoNameservers(
        request=dns.message.make_query(ZONE, "NS"), errors=[]
    )
    outcome, _ = run(script)
    assert outcome.status == "ok"
    assert outcome.data["ns"] == {"found": None, "error": "servfail"}
    assert outcome.data["caa"]["found"] is True


def test_everything_is_storable_as_json() -> None:
    import json

    json.dumps(run(healthy())[0].data)
