"""Run the rules over the facts of a scan and turn what they decided into findings.

The engine is pure: facts in, findings out. It calls every rule for the subjects it judges (every
host, every public address, the domain), isolates failures (a rule that crashes costs its own
findings and nothing else), cleans and bounds what the rules return, gives each result its stable
fingerprint and removes duplicates. Persisting the findings is ``app/service/findings.py``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.rules.base import (
    CONFIDENCE_RANK,
    RULES,
    SEVERITY_RANK,
    Attribution,
    Confidence,
    DomainFacts,
    Draft,
    HostFacts,
    IpFacts,
    Result,
    Rule,
    RuleSettings,
    Severity,
    fingerprint,
)

log = logging.getLogger(__name__)

MAX_FINDINGS = 5000  # per scan; the rest is dropped, lowest severity first, and counted
MAX_STRING = 300
MAX_ITEMS = 20
MAX_EVIDENCE = 20
MAX_DEPTH = 4


@dataclass(frozen=True)
class ScanFacts:
    """Everything a scan collected, as the rules see it."""

    domain: str
    hosts: Sequence[HostFacts]
    domain_results: Mapping[str, Result]


@dataclass(frozen=True)
class RuleFinding:
    """A rule's decision with its identity: the row that ends up in the findings table."""

    rule_id: str
    rule_version: int
    fingerprint: str
    subject: str
    severity: Severity
    confidence: Confidence
    attribution: Attribution
    params: dict[str, Any]
    evidence: tuple[str, ...]
    host_id: str | None


@dataclass
class Evaluation:
    findings: list[RuleFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # ids of rules that crashed
    dropped: int = 0  # findings cut by MAX_FINDINGS


def jsonable(value: Any, depth: int = 0) -> Any:
    """``value`` as bounded JSON data: strings, lists and nesting are cut, odd types become text."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:MAX_STRING]
    if depth >= MAX_DEPTH:
        return str(value)[:MAX_STRING]
    if isinstance(value, Mapping):
        return {str(k)[:60]: jsonable(v, depth + 1) for k, v in list(value.items())[:MAX_ITEMS]}
    if isinstance(value, Iterable):
        return [jsonable(v, depth + 1) for v in list(value)[:MAX_ITEMS]]
    return str(value)[:MAX_STRING]


def ip_facts(hosts: Sequence[HostFacts]) -> list[IpFacts]:
    """One ``IpFacts`` per public address that ports data exists for, sorted by address.

    The same address shows up in the ports result of every host that resolves to it (cached, so
    identical). It is shared infrastructure as soon as any host's result says so, and attributed to
    a host name as soon as the provider lists one.
    """
    by_ip: dict[str, list[tuple[HostFacts, Mapping[str, Any], str]]] = {}
    for host in sorted(hosts, key=lambda h: h.hostname):
        ports = host.ok("ports")
        if ports is None:
            continue
        for entry in ports.data.get("addresses", []):
            if entry.get("status") == "ok" and entry.get("facts") and entry.get("ip"):
                by_ip.setdefault(str(entry["ip"]), []).append((host, entry, ports.id))
    result: list[IpFacts] = []
    for ip in sorted(by_ip):
        rows = by_ip[ip]
        attributions = {str(entry.get("attribution")) for _, entry, _ in rows}
        attribution: Attribution = (
            "shared_infrastructure"
            if "shared_infrastructure" in attributions
            else "hostname_supported"
            if "hostname_supported" in attributions
            else "ip_only"
        )
        facts = rows[0][1]["facts"]
        result.append(
            IpFacts(
                ip=ip,
                facts=facts,
                provider=str(facts.get("provider") or ""),
                attribution=attribution,
                hosts=[host for host, _, _ in rows],
                evidence=list(dict.fromkeys(rid for _, _, rid in rows))[:MAX_EVIDENCE],
            )
        )
    return result


def _run(rule: Rule, subject: Any, settings: RuleSettings, out: Evaluation) -> list[Draft]:
    try:
        return list(rule.evaluate(subject, settings))
    except Exception:
        log.exception("rule %s crashed", rule.id)
        if rule.id not in out.errors:
            out.errors.append(rule.id)
        return []


def _finding(rule: Rule, draft: Draft) -> RuleFinding:
    subject = draft.subject[:255]
    return RuleFinding(
        rule_id=rule.id,
        rule_version=rule.version,
        fingerprint=fingerprint(rule.id, subject),
        subject=subject,
        severity=draft.severity,
        confidence=draft.confidence,
        attribution=draft.attribution,
        params=jsonable(draft.params),
        evidence=tuple(draft.evidence[:MAX_EVIDENCE]),
        host_id=draft.host_id,
    )


def _better(candidate: RuleFinding, kept: RuleFinding) -> bool:
    return (SEVERITY_RANK[candidate.severity], CONFIDENCE_RANK[candidate.confidence]) > (
        SEVERITY_RANK[kept.severity],
        CONFIDENCE_RANK[kept.confidence],
    )


def evaluate(
    facts: ScanFacts, settings: RuleSettings, rules: Mapping[str, Rule] | None = None
) -> Evaluation:
    """Judge a scan: every rule for every subject it applies to."""
    chosen = RULES if rules is None else rules
    out = Evaluation()
    produced: list[tuple[Rule, Draft]] = []
    hosts = sorted(facts.hosts, key=lambda h: h.hostname)
    addresses = ip_facts(hosts)
    domain = DomainFacts(facts.domain, facts.domain_results)
    for rule in chosen.values():
        subjects: list[Any]
        if rule.scope == "host":
            subjects = list(hosts)
        elif rule.scope == "ip":
            subjects = list(addresses)
        else:
            subjects = [domain]
        for subject in subjects:
            produced.extend((rule, draft) for draft in _run(rule, subject, settings, out))

    unique: dict[str, RuleFinding] = {}
    for rule, draft in produced:
        finding = _finding(rule, draft)
        kept = unique.get(finding.fingerprint)
        if kept is None:
            unique[finding.fingerprint] = finding
            continue
        winner, other = (finding, kept) if _better(finding, kept) else (kept, finding)
        merged = tuple(dict.fromkeys([*winner.evidence, *other.evidence]))[:MAX_EVIDENCE]
        unique[finding.fingerprint] = RuleFinding(**{**winner.__dict__, "evidence": merged})

    ordered = sorted(
        unique.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.subject)
    )
    out.findings = ordered[:MAX_FINDINGS]
    out.dropped = max(0, len(ordered) - MAX_FINDINGS)
    return out
