"""Rule interpretation engine translating observations into structured, versioned findings."""

from __future__ import annotations

from app.service.checks.tls import CheckFinding
from app.service.checks.webrisk import WebRiskResult

RULES_ENGINE_VERSION = "v1"


def cvss_to_severity(score: float | None) -> str:
    """Map CVSS v3 score to platform severity."""
    if score is None:
        return "informational"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "informational"


def evaluate_webrisk_findings(
    result: WebRiskResult,
    rule_version: str = RULES_ENGINE_VERSION,
) -> list[CheckFinding]:
    """Generate findings from a Web Risk reputation check."""
    findings: list[CheckFinding] = []
    subject_key = f"url:{result.url}"

    if result.status == "unlicensed" or result.status == "failed":
        findings.append(
            CheckFinding(
                rule_id="COLLECTION_INCOMPLETE",
                rule_version=rule_version,
                subject_key=subject_key,
                severity="informational",
                confidence="unknown",
                attribution="hostname_supported",
                message_key="rules.collection_incomplete",
                message_parameters={
                    "check": "url_reputation",
                    "reason_code": result.reason_code,
                    "url": result.url,
                },
            )
        )
        return findings

    if result.verdict == "match" and result.threats:
        threat_names = [t.threat_type for t in result.threats]
        findings.append(
            CheckFinding(
                rule_id="REPUTATION_MATCH",
                rule_version=rule_version,
                subject_key=subject_key,
                severity="high",
                confidence="high",
                attribution="hostname_supported",
                message_key="rules.reputation_match",
                message_parameters={
                    "url": result.url,
                    "threat_types": threat_names,
                },
            )
        )

    return findings
