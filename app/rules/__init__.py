"""The rules: pure functions that turn stored check results into findings.

Importing this package registers every rule (``RULES``); ``evaluate`` runs them over a scan's
facts. The rule catalogue in ``docs/rules.md`` is generated from the registry
(``app.rules.docs``) and a test keeps the file in step with the code.
"""

from __future__ import annotations

from app.rules import domain, host, ip  # noqa: F401 - importing registers the rules
from app.rules.base import (
    CONFIDENCE_RANK,
    RULES,
    SEVERITY_RANK,
    DomainFacts,
    Draft,
    HostFacts,
    IpFacts,
    Result,
    Rule,
    RuleSettings,
    fingerprint,
)
from app.rules.engine import Evaluation, RuleFinding, ScanFacts, evaluate, ip_facts

__all__ = [
    "CONFIDENCE_RANK",
    "RULES",
    "SEVERITY_RANK",
    "DomainFacts",
    "Draft",
    "Evaluation",
    "HostFacts",
    "IpFacts",
    "Result",
    "Rule",
    "RuleFinding",
    "RuleSettings",
    "ScanFacts",
    "evaluate",
    "fingerprint",
    "ip_facts",
]
