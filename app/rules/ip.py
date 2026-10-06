"""Rules that judge one public address: what a scanner saw open on it, and the CVEs it reports.

Ports and CVEs belong to the *address*, so these rules run once per address, however many hosts of
the scan resolve to it (the finding lists those hosts). An address that is shared infrastructure
(a CDN edge, a hosting platform with many tenants) says nothing about the vendor's own servers:
no finding is made for it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from app.rules.base import N_, Draft, IpFacts, RuleSettings, Severity, ip_rule

MAX_HOSTS_LISTED = 5
EPSS_MEDIUM = 0.5  # an estimated 50 % chance of exploitation within 30 days
EPSS_LOW = 0.1
RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    21: ("medium", "FTP"),
    22: ("medium", "SSH"),
    23: ("high", "Telnet"),
    445: ("high", "SMB"),
    3306: ("high", "MySQL"),
    3389: ("high", "RDP"),
    5432: ("high", "PostgreSQL"),
    6379: ("high", "Redis"),
    9200: ("high", "Elasticsearch"),
    11211: ("high", "Memcached"),
    27017: ("high", "MongoDB"),
}


def _hosts(ip: IpFacts) -> list[dict[str, str]]:
    return [{"id": h.id, "hostname": h.hostname} for h in ip.hosts[:MAX_HOSTS_LISTED]]


def _own(ip: IpFacts) -> bool:
    return ip.attribution != "shared_infrastructure"


@ip_rule(
    "RISKY_PORT_EXPOSED",
    title=N_("Risky service reachable from the internet"),
    summary=N_("A scanner saw %(service)s (port %(port)s) open on %(ip)s."),
    advice=N_(
        "Databases, remote administration and file sharing should not be reachable from the "
        "internet; ask the vendor to restrict them."
    ),
    trigger="A port of a risky service (FTP, SSH, Telnet, SMB, RDP, MySQL, PostgreSQL, Redis, "
    "Elasticsearch, Memcached, MongoDB) was observed open. High for databases, remote "
    "administration and file sharing, Medium for FTP and SSH. The data is a scanner's snapshot, "
    "so confidence is medium. Addresses of shared infrastructure are skipped.",
    severities=("medium", "high"),
    checks=("ports",),
    labels={
        "hosts": N_("Hosts on this address"),
        "product": N_("Product"),
        "version": N_("Version"),
    },
)
def risky_port_exposed(ip: IpFacts, settings: RuleSettings) -> Iterator[Draft]:
    if not _own(ip):
        return
    seen: set[int] = set()
    for service in ip.facts.get("services", []):
        port = service.get("port")
        if not isinstance(port, int) or port in seen or port not in RISKY_PORTS:
            continue
        seen.add(port)
        severity, name = RISKY_PORTS[port]
        yield Draft(
            f"ip:{ip.ip}:{port}",
            severity,
            "medium",
            ip.attribution,
            {
                "ip": ip.ip,
                "port": port,
                "service": name,
                "product": service.get("product"),
                "version": service.get("version"),
                "hosts": [h["hostname"] for h in _hosts(ip)],
                "host_count": len(ip.hosts),
                "host_ids": [h["id"] for h in _hosts(ip)],
            },
            tuple(ip.evidence),
            None,
        )


@ip_rule(
    "CVE_OBSERVED",
    version=2,
    title=N_("Known vulnerabilities reported"),
    summary=N_(
        "%(count)s CVEs are reported for software seen on %(ip)s; they are leads to verify, "
        "not confirmed vulnerabilities."
    ),
    advice=N_(
        "Ask the vendor which of these apply and how patching is tracked, starting with the ones "
        "that are known to be exploited."
    ),
    trigger="The provider lists CVE identifiers for the address (it derives them from software "
    "versions it read, so they are leads, not proof). The severity follows what is known about "
    "the exploitation of those CVEs: High when one is on CISA's Known Exploited Vulnerabilities "
    "list, Medium when the highest EPSS score is 0.5 or more (an estimated chance of "
    "exploitation within 30 days of 50 %), Low from 0.1, otherwise Informational. When the "
    "exploitation data is not installed the finding stays Informational and says that it was "
    "not ranked. Confidence is Medium when the provider verified a CVE, otherwise Low. Addresses "
    "of shared infrastructure are skipped.",
    severities=("informational", "low", "medium", "high"),
    checks=("ports",),
    labels={
        "top": N_("Examples"),
        "kev": N_("Known to be exploited (CISA KEV)"),
        "ransomware": N_("Used in ransomware campaigns"),
        "max_epss": N_("Highest EPSS score"),
        "max_cvss": N_("Highest CVSS score"),
        "ranked_by": N_("Ranked by"),
        "exploit_stale": N_("Exploitation data out of date"),
        "hosts": N_("Hosts on this address"),
    },
)
def cve_observed(ip: IpFacts, settings: RuleSettings) -> Iterator[Draft]:
    vulnerabilities: list[dict[str, Any]] = list(ip.facts.get("vulnerabilities", []))
    if not _own(ip) or not vulnerabilities:
        return
    exploit: Mapping[str, Any] = ip.facts.get("exploit_data") or {}
    listed = [v for v in vulnerabilities if isinstance(v.get("kev"), dict)]
    top_epss = max(
        (v for v in vulnerabilities if _epss(v) is not None),
        key=lambda v: _epss(v) or 0.0,
        default=None,
    )
    highest = _epss(top_epss) if top_epss else None
    severity: Severity = "informational"
    if listed:
        severity = "high"
    elif highest is not None and highest >= EPSS_MEDIUM:
        severity = "medium"
    elif highest is not None and highest >= EPSS_LOW:
        severity = "low"
    scored = [v for v in vulnerabilities if isinstance(v.get("cvss"), int | float)]
    scored.sort(key=lambda v: -float(v["cvss"]))
    # the examples: known exploited first, then by EPSS, then by CVSS (the check sorted them so)
    top = [str(v["id"]) for v in vulnerabilities[:5]]
    verified = any(v.get("verified") is True for v in vulnerabilities)
    yield Draft(
        f"ip:{ip.ip}",
        severity,
        "medium" if verified else "low",
        ip.attribution,
        {
            "ip": ip.ip,
            "count": len(vulnerabilities),
            "top": top,
            "kev": [str(v["id"]) for v in listed[:5]],
            "ransomware": True if any(v["kev"].get("ransomware") for v in listed) else None,
            "max_epss": highest,
            "max_cvss": float(scored[0]["cvss"]) if scored else None,
            "ranked_by": str(exploit.get("ranked_by") or "none"),
            "exploit_stale": True if exploit.get("stale") else None,
            "hosts": [h["hostname"] for h in _hosts(ip)],
            "host_ids": [h["id"] for h in _hosts(ip)],
            "provider": ip.provider,
        },
        tuple(ip.evidence),
        None,
    )


def _epss(vulnerability: Mapping[str, Any]) -> float | None:
    """The EPSS score of a CVE, if the check found one."""
    epss = vulnerability.get("epss")
    score = epss.get("score") if isinstance(epss, dict) else None
    return float(score) if isinstance(score, int | float) and not isinstance(score, bool) else None
