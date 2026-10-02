"""Shodan host inspection adapter with strict outcome typing and attribution."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

import httpx

SHODAN_SCHEMA_VERSION = 1
SHODAN_ADAPTER_VERSION = "shodan-v1"

# Known shared infrastructure / CDN identifiers
_SHARED_INFRA_KEYWORDS = frozenset(
    {
        "cloudflare",
        "cloudfront",
        "akamai",
        "fastly",
        "incapsula",
        "imperva",
        "sucuri",
        "azure edge",
        "google user content",
        "edgecast",
    }
)


@dataclass(frozen=True)
class ShodanCVE:
    """Individual CVE vulnerability observation from Shodan."""

    cve_id: str
    cvss_score: float | None = None
    summary: str | None = None
    verified: bool = False
    attribution: str = "ip_only"  # 'shared_infrastructure', 'ip_only', 'hostname_supported'

    def to_dict(self) -> dict[str, Any]:
        """Convert CVE to dictionary."""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "summary": self.summary,
            "verified": self.verified,
            "attribution": self.attribution,
        }


@dataclass(frozen=True)
class ShodanService:
    """Open port and service observation from Shodan."""

    port: int
    transport: str  # 'tcp', 'udp'
    product: str | None = None
    version: str | None = None
    cpe: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    banner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert service to dictionary."""
        return {
            "port": self.port,
            "transport": self.transport,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "hostnames": self.hostnames,
            "banner": self.banner,
        }


@dataclass(frozen=True)
class ShodanHostResult:
    """Immutable result of a Shodan IP host inspection."""

    ip: str
    status: str  # 'succeeded', 'unlicensed', 'failed'
    reason_code: str | None  # Diagnostic code on failure
    verdict: str  # 'match', 'no_match', 'unknown'
    is_shared_infrastructure: bool = False
    services: list[ShodanService] = field(default_factory=list)
    vulnerabilities: list[ShodanCVE] = field(default_factory=list)
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    hostnames: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    collected_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "ip": self.ip,
            "status": self.status,
            "reason_code": self.reason_code,
            "verdict": self.verdict,
            "is_shared_infrastructure": self.is_shared_infrastructure,
            "services": [s.to_dict() for s in self.services],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "hostnames": self.hostnames,
            "tags": self.tags,
            "collected_at": self.collected_at.isoformat(),
        }


def _is_shared_infra(
    org: str | None,
    isp: str | None,
    tags: list[str],
    hostnames: list[str],
) -> bool:
    """Determine if the IP belongs to a shared hosting / CDN infrastructure (FIND-01)."""
    text = f"{org or ''} {isp or ''}".lower()
    if any(keyword in text for keyword in _SHARED_INFRA_KEYWORDS):
        return True
    if any(t.lower() in ("cdn", "cloud", "shared") for t in tags):
        return True
    if len(hostnames) > 5:
        return True
    return False


def lookup_shodan_host(
    ip: str,
    api_key: str | None = None,
    target_hostname: str | None = None,
    http_client: httpx.Client | None = None,
    timeout: float = 10.0,
) -> ShodanHostResult:
    """Query Shodan Host API for open ports, services, and CVEs on a specific IP address.

    Enforces:
    - Diagnostic outcome separation (PRV-01):
      - 404 -> status="succeeded", verdict="no_match"
      - Missing API key -> status="unlicensed", reason_code="missing_api_key"
      - 429 -> status="failed", reason_code="quota_exhausted"
      - 401/403 -> status="failed", reason_code="auth_failed"
      - Timeout -> status="failed", reason_code="timeout"
    - Shared infrastructure attribution separation (FIND-01):
      - CVEs on shared IPs/CDNs are attributed as "shared_infrastructure" or "ip_only".
    """
    clean_ip = ip.strip().strip("[]")
    if not api_key:
        return ShodanHostResult(
            ip=clean_ip,
            status="unlicensed",
            reason_code="missing_api_key",
            verdict="unknown",
        )

    url = f"https://api.shodan.io/shodan/host/{clean_ip}"
    params = {"key": api_key, "minify": "false"}

    client = http_client or httpx.Client(timeout=timeout)
    should_close_client = http_client is None

    try:
        response = client.get(url, params=params)
    except httpx.TimeoutException:
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="timeout",
            verdict="unknown",
        )
    except httpx.RequestError:
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )
    finally:
        if should_close_client:
            client.close()

    # 1. 404 No information available for this IP
    if response.status_code == 404:
        return ShodanHostResult(
            ip=clean_ip,
            status="succeeded",
            reason_code=None,
            verdict="no_match",
        )

    # 2. 401 / 403 Authentication error
    if response.status_code in (401, 403):
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="auth_failed",
            verdict="unknown",
        )

    # 3. 429 Quota / Rate limit exceeded
    if response.status_code == 429:
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="quota_exhausted",
            verdict="unknown",
        )

    # 4. Other non-200 responses
    if response.status_code != 200:
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )

    # 5. Parse 200 OK payload
    try:
        payload = response.json()
    except Exception:
        return ShodanHostResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )

    org = payload.get("org")
    isp = payload.get("isp")
    asn = payload.get("asn")
    hostnames = payload.get("hostnames", [])
    tags = payload.get("tags", [])

    is_shared = _is_shared_infra(org, isp, tags, hostnames)

    # Parse services
    services: list[ShodanService] = []
    raw_data = payload.get("data", [])
    for item in raw_data:
        port = item.get("port")
        if not isinstance(port, int):
            continue
        transport = str(item.get("transport", "tcp")).lower()
        product = item.get("product")
        version = item.get("version")
        cpe = item.get("cpe", [])
        svc_hostnames = item.get("hostnames", [])
        banner = item.get("data", "")[:500] if item.get("data") else None

        services.append(
            ShodanService(
                port=port,
                transport=transport,
                product=product,
                version=version,
                cpe=cpe if isinstance(cpe, list) else [str(cpe)],
                hostnames=svc_hostnames if isinstance(svc_hostnames, list) else [],
                banner=banner,
            )
        )

    # Parse vulnerabilities
    vulnerabilities: list[ShodanCVE] = []
    vulns_dict = payload.get("vulns", {})
    if isinstance(vulns_dict, dict):
        for cve_id, meta in vulns_dict.items():
            cvss = None
            summary = None
            verified = False
            if isinstance(meta, dict):
                cvss_val = meta.get("cvss")
                if isinstance(cvss_val, (int, float)):
                    cvss = float(cvss_val)
                summary = meta.get("summary")
                verified = bool(meta.get("verified", False))

            # Attribution evaluation (FIND-01)
            if is_shared:
                attribution = "shared_infrastructure"
            elif target_hostname and target_hostname.lower() in [h.lower() for h in hostnames]:
                attribution = "hostname_supported"
            else:
                attribution = "ip_only"

            vulnerabilities.append(
                ShodanCVE(
                    cve_id=str(cve_id),
                    cvss_score=cvss,
                    summary=summary,
                    verified=verified,
                    attribution=attribution,
                )
            )

    return ShodanHostResult(
        ip=clean_ip,
        status="succeeded",
        reason_code=None,
        verdict="match" if (services or vulnerabilities) else "no_match",
        is_shared_infrastructure=is_shared,
        services=services,
        vulnerabilities=vulnerabilities,
        org=org,
        isp=isp,
        asn=asn,
        hostnames=hostnames,
        tags=tags,
    )
