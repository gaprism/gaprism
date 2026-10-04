"""Shodan InternetDB: free, keyless, updated weekly - open ports, CPEs, hostnames, tags, CVE ids.

Free for non-commercial use only (see docs/checks-catalog.md). It has no banners, versions per
port or CVSS scores; use the Shodan host API (``shodan.py``) for those.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.service.ports.models import (
    CVE_ID,
    MAX_SERVICES,
    MAX_VULNERABILITIES,
    PortFacts,
    PortService,
    PortsLookup,
    Vulnerability,
    clean_list,
)
from app.service.ratelimit import RateLimiter

URL = "https://internetdb.shodan.io/{ip}"


def parse_internetdb(ip: str, payload: object) -> PortFacts | None:
    """Facts from an InternetDB answer, ``None`` if the answer is not what we expect."""
    if not isinstance(payload, dict):
        return None
    raw_ports = payload.get("ports")
    ports = (
        [p for p in raw_ports if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536]
        if isinstance(raw_ports, list)
        else []
    )
    raw_vulns = payload.get("vulns")
    cves = (
        sorted({v for v in raw_vulns if isinstance(v, str) and CVE_ID.fullmatch(v)})
        if isinstance(raw_vulns, list)
        else []
    )
    return PortFacts(
        ip=ip,
        provider="internetdb",
        services=tuple(PortService(port) for port in sorted(set(ports))[:MAX_SERVICES]),
        vulnerabilities=tuple(Vulnerability(cve) for cve in cves[:MAX_VULNERABILITIES]),
        hostnames=clean_list(payload.get("hostnames")),
        tags=clean_list(payload.get("tags")),
        cpes=clean_list(payload.get("cpes")),
    )


class InternetDbProvider:
    name = "internetdb"

    def __init__(self, client: httpx.Client, limiter: RateLimiter) -> None:
        self._client = client
        self._limiter = limiter

    def lookup(self, ip: str) -> PortsLookup:
        self._limiter.acquire()
        try:
            response = self._client.get(URL.format(ip=ip), headers={"Accept": "application/json"})
        except httpx.TimeoutException:
            return PortsLookup("error", "timeout")
        except httpx.HTTPError:
            return PortsLookup("error", "connection_failed")
        if response.status_code == 404:
            return PortsLookup("no_data", "no_information")
        if response.status_code == 429:
            return PortsLookup("unavailable", "rate_limited")
        if response.status_code != 200:
            return PortsLookup("error", f"http_{response.status_code}")
        try:
            payload: Any = response.json()
        except ValueError:
            return PortsLookup("error", "invalid_response")
        facts = parse_internetdb(ip, payload)
        if facts is None:
            return PortsLookup("error", "invalid_response")
        return PortsLookup("ok", facts=facts)
