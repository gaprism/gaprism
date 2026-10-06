"""The rule engine: fingerprints, isolation, dedup, bounds, the registry, and the whole rule set
over scans that trip every rule."""

from __future__ import annotations

import datetime as dt
import logging
import re
import uuid
from typing import Any

import pytest

import app.rules.engine as engine_module
from app.checks import REGISTRY
from app.checks.base import CheckOutcome
from app.models import Finding
from app.rules import (
    RULES,
    SEVERITY_RANK,
    DomainFacts,
    Draft,
    HostFacts,
    Rule,
    ScanFacts,
    evaluate,
    fingerprint,
    ip_facts,
)
from app.rules.engine import jsonable
from app.service.findings import describe
from tests.rules import scenario
from tests.rules.helpers import DOMAIN, host, result, settings
from tests.rules.test_ip_rules import ports_result

SEVERITIES = {"informational", "low", "medium", "high", "critical"}


# ------------------------------------------------------------------------------ fingerprints


def test_a_fingerprint_is_stable_and_depends_on_the_rule_and_the_subject_only() -> None:
    first = fingerprint("TLS_INVALID", "host:www.example.com")
    assert first == fingerprint("TLS_INVALID", "host:www.example.com")
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert first != fingerprint("TLS_INVALID", "host:api.example.com")
    assert first != fingerprint("TLS_EXPIRES_SOON", "host:www.example.com")


def test_the_fingerprint_of_a_real_finding_survives_a_change_of_severity_and_a_rescan() -> None:
    def findings(days: int) -> list[Any]:
        facts = ScanFacts(
            DOMAIN, [host("a.example.com", tls=scenario.tls(days_until_expiration=days))], {}
        )
        return [f for f in evaluate(facts, settings()).findings if f.rule_id == "TLS_EXPIRES_SOON"]

    (soon,), (sooner,) = findings(20), findings(3)
    assert (soon.severity, sooner.severity) == ("low", "medium")
    assert soon.fingerprint == sooner.fingerprint  # the same finding, now more urgent


# ------------------------------------------------------------------------------ custom rules


def rule(rule_id: str, scope: str, evaluate_fn: Any) -> Rule:
    return Rule(
        id=rule_id,
        version=1,
        scope=scope,  # type: ignore[arg-type]
        title="t",
        summary="s",
        advice="a",
        trigger="x",
        severities=("low",),
        checks=(),
        labels={},
        evaluate=evaluate_fn,
    )


def draft(subject: str, severity: str = "low", **kwargs: Any) -> Draft:
    return Draft(
        subject, severity, "high", "domain", kwargs.pop("params", {}), kwargs.pop("evidence", ())
    )  # type: ignore[arg-type]


def facts_with(*names: str) -> ScanFacts:
    return ScanFacts(DOMAIN, [host(name) for name in names], {})


def test_rules_run_for_every_host_every_address_and_the_domain_once() -> None:
    seen: dict[str, list[str]] = {"host": [], "ip": [], "domain": []}

    def host_rule(h: HostFacts, s: Any) -> list[Draft]:
        seen["host"].append(h.hostname)
        return []

    def ip_rule(ip: Any, s: Any) -> list[Draft]:
        seen["ip"].append(ip.ip)
        return []

    def domain_rule(d: DomainFacts, s: Any) -> list[Draft]:
        seen["domain"].append(d.domain)
        return []

    rules = {
        "H": rule("H", "host", host_rule),
        "I": rule("I", "ip", ip_rule),
        "D": rule("D", "domain", domain_rule),
    }
    hosts = [
        host("b.example.com", ports=ports_result("b.example.com", address="93.184.216.35")),
        host("a.example.com", ports=ports_result("a.example.com")),
    ]
    evaluate(ScanFacts(DOMAIN, hosts, {}), settings(), rules)
    assert seen == {
        "host": ["a.example.com", "b.example.com"],  # sorted, whatever order they came in
        "ip": ["93.184.216.34", "93.184.216.35"],
        "domain": [DOMAIN],
    }


def test_a_crashing_rule_costs_only_its_own_findings(caplog: pytest.LogCaptureFixture) -> None:
    def fragile(h: HostFacts, s: Any) -> list[Draft]:
        if h.hostname == "b.example.com":
            raise RuntimeError("boom with a secret detail")
        return [draft(f"host:{h.hostname}")]

    def steady(h: HostFacts, s: Any) -> list[Draft]:
        return [draft(f"host:{h.hostname}")]

    rules = {"FRAGILE": rule("FRAGILE", "host", fragile), "STEADY": rule("STEADY", "host", steady)}
    with caplog.at_level(logging.ERROR, logger="app.rules.engine"):
        out = evaluate(
            facts_with("a.example.com", "b.example.com", "c.example.com"), settings(), rules
        )

    assert out.errors == ["FRAGILE"]  # reported once, however often it crashed
    pairs = sorted((f.rule_id, f.subject) for f in out.findings)
    assert pairs == [
        ("FRAGILE", "host:a.example.com"),
        ("FRAGILE", "host:c.example.com"),  # the other hosts of the same rule still ran
        ("STEADY", "host:a.example.com"),
        ("STEADY", "host:b.example.com"),
        ("STEADY", "host:c.example.com"),
    ]
    assert "rule FRAGILE crashed" in caplog.text


def test_duplicates_collapse_to_the_most_serious_with_all_the_evidence() -> None:
    def twice(h: HostFacts, s: Any) -> list[Draft]:
        return [
            draft("host:x", "low", evidence=("r1",)),
            draft("host:x", "high", evidence=("r2",)),
            draft("host:x", "medium", evidence=("r2", "r3")),
        ]

    out = evaluate(facts_with("a.example.com"), settings(), {"T": rule("T", "host", twice)})
    (only,) = out.findings
    assert (only.severity, only.subject) == ("high", "host:x")
    assert only.evidence == ("r2", "r1", "r3")  # the winner's first, nothing twice


def test_equal_severity_prefers_the_surer_finding() -> None:
    def sure(h: HostFacts, s: Any) -> list[Draft]:
        return [
            Draft("host:x", "medium", "low", "domain", {"which": "unsure"}),
            Draft("host:x", "medium", "high", "domain", {"which": "sure"}),
        ]

    (only,) = evaluate(
        facts_with("a.example.com"), settings(), {"S": rule("S", "host", sure)}
    ).findings
    assert only.params["which"] == "sure"


def test_findings_come_most_serious_first_then_by_rule_and_subject() -> None:
    def build(severity: str) -> Any:
        return lambda h, s: [draft(f"host:{h.hostname}", severity)]

    rules = {
        "B_LOW": rule("B_LOW", "host", build("low")),
        "A_LOW": rule("A_LOW", "host", build("low")),
        "C_HIGH": rule("C_HIGH", "host", build("high")),
        "D_INFO": rule("D_INFO", "host", build("informational")),
    }
    out = evaluate(facts_with("b.example.com", "a.example.com"), settings(), rules)
    assert [(f.severity, f.rule_id, f.subject) for f in out.findings] == [
        ("high", "C_HIGH", "host:a.example.com"),
        ("high", "C_HIGH", "host:b.example.com"),
        ("low", "A_LOW", "host:a.example.com"),
        ("low", "A_LOW", "host:b.example.com"),
        ("low", "B_LOW", "host:a.example.com"),
        ("low", "B_LOW", "host:b.example.com"),
        ("informational", "D_INFO", "host:a.example.com"),
        ("informational", "D_INFO", "host:b.example.com"),
    ]


def test_one_rule_with_several_severities_for_one_subject_yields_the_most_serious() -> None:
    def many(h: HostFacts, s: Any) -> list[Draft]:
        return [
            draft(f"host:{h.hostname}", sev) for sev in ("low", "high", "informational", "medium")
        ]

    out = evaluate(facts_with("a.example.com"), settings(), {"M": rule("M", "host", many)})
    assert [f.severity for f in out.findings] == ["high"]


def test_the_number_of_findings_is_capped_and_the_least_serious_go_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine_module, "MAX_FINDINGS", 5)

    def lots(d: DomainFacts, s: Any) -> list[Draft]:
        return [draft(f"domain:{n}", "high" if n < 3 else "low") for n in range(20)]

    out = evaluate(ScanFacts(DOMAIN, [], {}), settings(), {"L": rule("L", "domain", lots)})
    assert len(out.findings) == 5 and out.dropped == 15
    assert [f.severity for f in out.findings] == ["high"] * 3 + ["low"] * 2


def test_what_a_rule_returns_is_cleaned_and_bounded() -> None:
    class Odd:
        def __str__(self) -> str:
            return "odd" * 200

    def messy(d: DomainFacts, s: Any) -> list[Draft]:
        params = {
            "long": "x" * 5000,
            "many": list(range(100)),
            "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}},
            "when": dt.date(2026, 10, 5),
            "set": {1},
            "odd": Odd(),
            5: "int key",
        }
        return [
            Draft(
                "domain:" + "s" * 400,
                "low",
                "high",
                "domain",
                params,
                tuple(f"r{n}" for n in range(50)),
            )
        ]

    (only,) = evaluate(
        ScanFacts(DOMAIN, [], {}), settings(), {"M": rule("M", "domain", messy)}
    ).findings
    assert len(only.subject) == 255 and len(only.evidence) == 20
    assert len(only.params["long"]) == 300 and len(only.params["many"]) == 20
    assert only.params["deep"]["a"]["b"]["c"] != {"d": {"e": 1}}  # cut at the depth limit
    assert only.params["when"] == "2026-10-05" and only.params["set"] == [1]
    assert len(only.params["odd"]) == 300 and only.params["5"] == "int key"


def test_jsonable_keeps_plain_json_untouched() -> None:
    value = {"a": [1, 2.5, True, None, "x"], "b": {"c": "d"}}
    assert jsonable(value) == value


# ------------------------------------------------------------------------------ addresses


def test_address_facts_merge_what_several_hosts_say_about_one_address() -> None:
    from tests.rules.test_ip_rules import IP

    a = host("a.example.com", ports=ports_result("a.example.com"))
    b = host("b.example.com", ports=ports_result("b.example.com", ports=((22, "tcp", None, None),)))
    broken = host("c.example.com", ports=CheckOutcome("error", "timeout"))
    nothing = host("d.example.com")
    (address,) = ip_facts([b, a, broken, nothing])
    assert address.ip == IP and [h.hostname for h in address.hosts] == [
        "a.example.com",
        "b.example.com",
    ]
    assert len(address.evidence) == 2 and address.provider == "shodan"
    assert address.attribution == "hostname_supported" or address.attribution == "ip_only"


def test_the_ports_of_an_address_that_was_not_found_are_not_facts() -> None:
    absent = CheckOutcome(
        "ok",
        data={
            "addresses": [
                {"ip": "1.2.3.4", "status": "no_data", "facts": None, "attribution": None}
            ]
        },
    )
    assert ip_facts([host("a.example.com", ports=absent)]) == []


# ------------------------------------------------------------------------------ the registry


def test_every_rule_is_documented_and_consistent() -> None:
    known_checks = set(REGISTRY)
    ids = list(RULES)
    assert len(ids) == len(set(ids)) and len(ids) >= 25
    for rule_id, current in RULES.items():
        assert re.fullmatch(r"[A-Z][A-Z0-9_]+", rule_id) and current.id == rule_id
        assert current.version >= 1 and current.scope in ("host", "ip", "domain")
        assert current.title and current.summary and current.advice and current.trigger
        assert current.severities and set(current.severities) <= SEVERITIES
        ranks = [SEVERITY_RANK[s] for s in current.severities]
        assert ranks == sorted(ranks)  # lowest first
        assert current.checks and set(current.checks) <= known_checks, rule_id
        assert set(current.labels) <= set(
            re.findall(r"(?:\w+)", " ".join(current.labels)) + list(current.labels)
        )
        for name in re.findall(r"%\((\w+)\)s", current.summary):
            assert name.isidentifier()


def test_the_required_rules_exist_with_their_documented_severities() -> None:
    assert RULES["LOCATION_OUTSIDE_EU_CH"].severities == ("medium", "high")
    assert RULES["PUBLIC_BREACH_HISTORY"].severities == ("medium", "high")
    assert RULES["TLS_INVALID"].severities == ("medium", "high")
    assert RULES["CVE_OBSERVED"].severities == ("informational", "low", "medium", "high")


# ------------------------------------------------------------------------------ the whole set


@pytest.fixture(scope="module")
def evaluations() -> list[Any]:
    return [evaluate(facts, settings()) for facts in scenario.scans()]


def test_between_them_the_scenarios_trip_every_rule(evaluations: list[Any]) -> None:
    fired = {f.rule_id for out in evaluations for f in out.findings}
    assert fired == set(RULES), f"never fired: {sorted(set(RULES) - fired)}"
    assert all(out.errors == [] for out in evaluations)


def test_every_finding_reads_as_a_sentence(evaluations: list[Any]) -> None:
    """Each rule's message formats from its parameters, with nothing left over or missing."""
    shown: set[str] = set()
    for out in evaluations:
        for found in out.findings:
            row = Finding(
                id=uuid.uuid4(),
                scan_id=uuid.uuid4(),
                host_id=None,
                rule_id=found.rule_id,
                rule_version=str(found.rule_version),
                subject=found.subject,
                severity=found.severity,
                confidence=found.confidence,
                attribution=found.attribution,
                params=found.params,
                evidence=list(found.evidence),
                fingerprint=found.fingerprint,
            )
            view = describe(row)
            assert view.title and view.advice, found.rule_id
            assert view.message and view.message != view.title, f"{found.rule_id}: {view.message}"
            assert "%(" not in view.message and "None" not in view.message, view.message
            assert found.severity in RULES[found.rule_id].severities
            shown.add(found.rule_id)
    assert shown == set(RULES)


def test_findings_are_deterministic(evaluations: list[Any]) -> None:
    again = [evaluate(facts, settings()) for facts in scenario.scans()]
    assert [[f.fingerprint for f in out.findings] for out in again] == [
        [f.fingerprint for f in out.findings] for out in evaluations
    ]


def test_a_sound_domain_with_healthy_hosts_has_no_findings() -> None:
    sound = scenario.sound_domain()
    healthy = host(
        "www.example.com",
        tls=scenario.tls(),
        http=scenario.web(),
        ip=scenario.located(scenario.swiss()),
    )
    facts = ScanFacts(DOMAIN, [healthy], {k: result(v) for k, v in sound.items()})
    out = evaluate(facts, settings())
    # the real example.com registration data is signed and locked; its breach list is empty
    assert [f.rule_id for f in out.findings] == [], out.findings


def test_the_scenarios_are_not_just_noise(evaluations: list[Any]) -> None:
    by_rule = {f.rule_id: f for out in evaluations for f in out.findings}
    assert by_rule["TLS_INVALID"].severity == "high"
    assert by_rule["LOCATION_OUTSIDE_EU_CH"].severity in ("high", "medium")
    assert by_rule["PUBLIC_BREACH_HISTORY"].severity == "high"  # March 2026 is recent in October
    assert by_rule["DOMAIN_EXPIRES_SOON"].severity == "medium"
