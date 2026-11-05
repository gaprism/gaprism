"""The shapes the rules work with: facts in, drafts out, and the registry that holds the rules.

A *rule* is a pure function. It reads facts (stored check results of one host, one IP address or
the domain) and returns zero or more ``Draft``s: what is wrong, how serious it is, how sure we are
and whose it is. Rules never touch the database or the network, and they never invent: a check that
was not ``ok`` simply gives a rule nothing to read, and "nothing to read" is never a finding (and
never a clean bill of health: the coverage of each scan is reported separately).

Severity and confidence are separate: a certificate that expired yesterday is *High* with *high*
confidence, a CDN edge outside the allowed area is *Medium* with *low* confidence. Whose a finding
is (``attribution``) is separate again: an open port seen on a CDN's shared address is not the
vendor's.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from app.messages import N_ as N_  # the rules import the marker from here

Severity = Literal["informational", "low", "medium", "high", "critical"]
Confidence = Literal["unknown", "low", "medium", "high"]
Attribution = Literal["hostname_supported", "ip_only", "shared_infrastructure", "domain"]
Scope = Literal["host", "ip", "domain"]

SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
CONFIDENCE_RANK: dict[str, int] = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


def fingerprint(rule_id: str, subject: str) -> str:
    """Stable identity of a finding across scans: the rule and what it is about.

    Severity, parameters and the rule version are not part of it, so a decision about a finding
    (S2.6) still applies after a re-scan, and after a rule is refined.
    """
    return hashlib.sha256(f"{rule_id}|{subject}".encode()).hexdigest()


# ------------------------------------------------------------------------------ facts


@dataclass(frozen=True)
class Result:
    """One stored check result, as far as the rules read it."""

    id: str
    status: str
    reason_code: str | None
    data: Mapping[str, Any]


@dataclass(frozen=True)
class HostFacts:
    """Everything the checks found out about one host."""

    id: str
    hostname: str
    source: str
    results: Mapping[str, Result]

    def ok(self, key: str) -> Result | None:
        """The result of check ``key`` if it succeeded (``ok``), else ``None``."""
        result = self.results.get(key)
        return result if result is not None and result.status == "ok" else None


@dataclass(frozen=True)
class DomainFacts:
    """The domain-level check results of a scan (email security, registration, ...)."""

    domain: str
    results: Mapping[str, Result]

    def ok(self, key: str) -> Result | None:
        result = self.results.get(key)
        return result if result is not None and result.status == "ok" else None

    def result(self, key: str) -> Result | None:
        return self.results.get(key)


@dataclass(frozen=True)
class IpFacts:
    """One public address that ports data exists for, and the hosts that resolve to it."""

    ip: str
    facts: Mapping[str, Any]  # the provider's facts (ports, services, vulnerabilities, ...)
    provider: str
    attribution: Attribution  # shared as soon as one host says so; then hostname_supported
    hosts: Sequence[HostFacts]
    evidence: Sequence[str]  # ids of the ports results this is read from


@dataclass(frozen=True)
class RuleSettings:
    """What a rule may be configured with, and the clock (so tests can fix the date)."""

    domain: str
    now: datetime
    allowed_countries: frozenset[str]
    breach_recent_months: int = 24


# ------------------------------------------------------------------------------ drafts


@dataclass(frozen=True)
class Draft:
    """What a rule decided. The engine adds the rule's id and version and the fingerprint."""

    subject: (
        str  # what it is about: ``host:www.example.com``, ``ip:93.184.216.34:22``, ``domain:...``
    )
    severity: Severity
    confidence: Confidence
    attribution: Attribution
    params: dict[str, Any] = field(default_factory=dict)  # JSON-safe facts for the message
    evidence: tuple[str, ...] = ()  # ids of the check results the decision is based on
    host_id: str | None = None


@dataclass(frozen=True)
class Rule:
    """A rule and what is needed to show and document it."""

    id: str
    version: int
    scope: Scope
    title: str  # short name (translatable)
    summary: str  # one sentence with %(name)s placeholders filled from the parameters
    advice: str  # what to ask the vendor, or what to do
    trigger: str  # when it fires, for docs/rules.md (English)
    severities: tuple[Severity, ...]  # every severity it can produce, lowest first
    checks: tuple[str, ...]  # the checks whose results it reads
    labels: Mapping[str, str]  # parameter -> label of the "facts" list on a finding
    evaluate: Callable[[Any, RuleSettings], Iterable[Draft]]


RULES: dict[str, Rule] = {}


def _register(rule: Rule) -> None:
    if rule.id in RULES:
        raise ValueError(f"Duplicate rule id {rule.id}")
    RULES[rule.id] = rule


def _decorator(
    scope: Scope,
    rule_id: str,
    *,
    title: str,
    summary: str,
    advice: str,
    trigger: str,
    severities: Sequence[Severity],
    checks: Sequence[str],
    labels: Mapping[str, str] | None = None,
    version: int = 1,
) -> Callable[[Callable[[Any, RuleSettings], Iterable[Draft]]], Callable[..., Iterable[Draft]]]:
    ordered = tuple(sorted(set(severities), key=lambda s: SEVERITY_RANK[s]))

    def register(
        function: Callable[[Any, RuleSettings], Iterable[Draft]],
    ) -> Callable[..., Iterable[Draft]]:
        _register(
            Rule(
                id=rule_id,
                version=version,
                scope=scope,
                title=title,
                summary=summary,
                advice=advice,
                trigger=trigger,
                severities=ordered,
                checks=tuple(checks),
                labels=dict(labels or {}),
                evaluate=function,
            )
        )
        return function

    return register


def host_rule(rule_id: str, **options: Any) -> Any:
    """Register a rule that runs once per host: ``evaluate(host: HostFacts, settings)``."""
    return _decorator("host", rule_id, **options)


def ip_rule(rule_id: str, **options: Any) -> Any:
    """Register a rule that runs once per public address: ``evaluate(ip: IpFacts, settings)``."""
    return _decorator("ip", rule_id, **options)


def domain_rule(rule_id: str, **options: Any) -> Any:
    """Register a rule that runs once per scan: ``evaluate(domain: DomainFacts, settings)``."""
    return _decorator("domain", rule_id, **options)
