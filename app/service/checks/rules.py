"""Rule interpretation engine translating observations into structured, versioned findings."""

from __future__ import annotations

from app.service.checks.shodan import ShodanHostResult
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


def evaluate_shodan_findings(
    result: ShodanHostResult,
    target_hostname: str | None = None,
    rule_version: str = RULES_ENGINE_VERSION,
) -> list[CheckFinding]:
    """Generate findings from a Shodan IP inspection (FIND-01)."""
    findings: list[CheckFinding] = []
    subject_key = f"ip:{result.ip}"

    if result.status in ("unlicensed", "failed"):
        findings.append(
            CheckFinding(
                rule_id="COLLECTION_INCOMPLETE",
                rule_version=rule_version,
                subject_key=subject_key,
                severity="informational",
                confidence="unknown",
                attribution="ip_only",
                message_key="rules.collection_incomplete",
                message_parameters={
                    "check": "shodan_host",
                    "reason_code": result.reason_code,
                    "ip": result.ip,
                },
            )
        )
        return findings

    # Service exposure findings
    for svc in result.services:
        svc_key = f"endpoint:{result.ip}:{svc.port}/{svc.transport}"
        findings.append(
            CheckFinding(
                rule_id="SERVICE_EXPOSURE_OBSERVED",
                rule_version=rule_version,
                subject_key=svc_key,
                severity="informational",
                confidence="high",
                attribution="shared_infrastructure"
                if result.is_shared_infrastructure
                else "ip_only",
                message_key="rules.service_exposure_observed",
                message_parameters={
                    "ip": result.ip,
                    "port": svc.port,
                    "transport": svc.transport,
                    "product": svc.product,
                    "version": svc.version,
                },
            )
        )

    # CVE findings with strict attribution (FIND-01)
    for vuln in result.vulnerabilities:
        severity = cvss_to_severity(vuln.cvss_score)
        # If on shared infrastructure, severity is downgraded to informational warning
        # unless hostname attribution is verified
        effective_severity = (
            "informational" if vuln.attribution == "shared_infrastructure" else severity
        )

        findings.append(
            CheckFinding(
                rule_id="SHODAN_CVE_OBSERVED",
                rule_version=rule_version,
                subject_key=f"ip:{result.ip}:cve:{vuln.cve_id}",
                severity=effective_severity,
                confidence="medium" if vuln.verified else "low",
                attribution=vuln.attribution,
                message_key="rules.shodan_cve_observed",
                message_parameters={
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "ip": result.ip,
                    "summary": vuln.summary,
                    "verified": vuln.verified,
                    "is_shared_infrastructure": result.is_shared_infrastructure,
                },
            )
        )

    return findings
