"""The Shodan host API: ports, services with products and versions, CVEs with scores.

The key travels in the query string (Shodan offers no header), so it must never reach a log
line or an error: exceptions are mapped to stable reason codes here and the log redaction filter
(``app/logging_redaction.py``) covers anything an HTTP library logs. Lookups of known hosts do
not use query credits; they are limited to about one request per second per key.

Response shape (from Shodan's documentation): top-level ``ports`` (list of ints), ``vulns``
(list of CVE ids), ``hostnames``, ``tags``, ``org``, ``isp``, ``asn``, ``os``, ``last_update`` and
``data`` (one banner per port with ``port``, ``transport``, ``product``, ``version``, ``cpe`` and,
per banner, ``vulns`` as an object ``{cve: {cvss, summary, verified}}``). Both ``vulns`` shapes are
accepted at both levels, and CVE ids are validated.
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
    clean_text,
)
from app.service.ratelimit import RateLimiter

URL = "https://api.shodan.io/shodan/host/{ip}"


def _score(value: object) -> float | None:
    """A CVSS score (0 to 10), or ``None``: anything else the provider sends is not a score."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if 0.0 <= value <= 10.0 else None  # NaN fails the comparison too


def _collect_vulnerabilities(payload: dict[str, Any]) -> tuple[Vulnerability, ...]:
    """Every valid CVE of the host, with the details Shodan gave for it (if any)."""
    found: dict[str, Vulnerability] = {}

    def add(cve: object, details: object) -> None:
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
            return
        known = found.get(cve) or Vulnerability(cve)
        info = details if isinstance(details, dict) else {}
        verified = info.get("verified")
        score = _score(info.get("cvss"))
        found[cve] = Vulnerability(
            cve,
            score if score is not None else known.cvss,
            clean_text(info.get("summary")) or known.summary,
            verified if isinstance(verified, bool) else known.verified,
        )

    def add_all(value: object) -> None:  # an object {cve: details} or a plain list of ids
        if isinstance(value, dict):
            for cve, details in value.items():
                add(cve, details)
        elif isinstance(value, list):
            for cve in value:
                add(cve, None)

    add_all(payload.get("vulns"))
    for banner in payload.get("data") or []:
        if isinstance(banner, dict):
            add_all(banner.get("vulns"))
    # Highest score first (unscored last), so a cut at the cap keeps the ones that matter.
    ranked = sorted(found.values(), key=lambda v: (v.cvss is None, -(v.cvss or 0.0), v.id))
    return tuple(ranked[:MAX_VULNERABILITIES])


def _collect_services(payload: dict[str, Any]) -> tuple[PortService, ...]:
    services: dict[tuple[int, str | None], PortService] = {}
    for banner in payload.get("data") or []:
        if not isinstance(banner, dict):
            continue
        port = banner.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            continue
        transport = clean_text(banner.get("transport"), 8)
        cpe = banner.get("cpe")
        services.setdefault(
            (port, transport),
            PortService(
                port,
                transport.lower() if transport else None,
                clean_text(banner.get("product"), 100),
                clean_text(banner.get("version"), 100),
                clean_list(cpe if isinstance(cpe, list) else [cpe] if cpe else []),
            ),
        )
    for port in payload.get("ports") or []:  # ports without a banner in `data`
        if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            if not any(key[0] == port for key in services):
                services[(port, None)] = PortService(port)
    return tuple(
        sorted(services.values(), key=lambda s: (s.port, s.transport or ""))[:MAX_SERVICES]
    )


def parse_shodan_host(ip: str, payload: object) -> PortFacts | None:
    if not isinstance(payload, dict) or "error" in payload:
        return None
    asn = clean_text(payload.get("asn"), 20)
    return PortFacts(
        ip=ip,
        provider="shodan",
        services=_collect_services(payload),
        vulnerabilities=_collect_vulnerabilities(payload),
        hostnames=clean_list(payload.get("hostnames")),
        tags=clean_list(payload.get("tags")),
        org=clean_text(payload.get("org"), 100),
        isp=clean_text(payload.get("isp"), 100),
        asn=asn,
        os=clean_text(payload.get("os"), 100),
        last_update=clean_text(payload.get("last_update"), 40),
    )


class ShodanProvider:
    name = "shodan"

    def __init__(self, client: httpx.Client, api_key: str, limiter: RateLimiter) -> None:
        self._client = client
        self._key = api_key
        self._limiter = limiter

    def lookup(self, ip: str) -> PortsLookup:
        self._limiter.acquire()
        try:
            response = self._client.get(URL.format(ip=ip), params={"key": self._key})
        except httpx.TimeoutException:
            return PortsLookup("error", "timeout")
        except httpx.HTTPError:  # never include the exception: its text can contain the URL
            return PortsLookup("error", "connection_failed")
        code = response.status_code
        if code == 404:
            return PortsLookup("no_data", "no_information")
        if code in (401, 403):
            return PortsLookup("unavailable", "invalid_key")
        if code == 402:
            return PortsLookup("unavailable", "membership_required")
        if code == 429:
            return PortsLookup("unavailable", "rate_limited")
        if code != 200:
            return PortsLookup("error", f"http_{code}")
        try:
            payload: Any = response.json()
        except ValueError:
            return PortsLookup("error", "invalid_response")
        facts = parse_shodan_host(ip, payload)
        if facts is None:
            return PortsLookup("error", "invalid_response")
        return PortsLookup("ok", facts=facts)
