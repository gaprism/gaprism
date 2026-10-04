"""GeoIP and ASN lookup adapter with dataset versioning and explicit error handling."""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from runner.dns import is_ip_public

GEOIP_SCHEMA_VERSION = 1
GEOIP_ADAPTER_VERSION = "geoip-v1"


@dataclass(frozen=True)
class GeoIPResult:
    """Immutable result of a GeoIP and ASN lookup."""

    ip: str
    status: str  # 'succeeded', 'unlicensed', 'failed'
    reason_code: str | None
    verdict: str  # 'match', 'no_match', 'unknown'
    iso_country_code: str | None = None
    country_name: str | None = None
    city_name: str | None = None
    asn: int | None = None
    as_org: str | None = None
    is_eu: bool = False
    database_version: str | None = None
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
            "iso_country_code": self.iso_country_code,
            "country_name": self.country_name,
            "city_name": self.city_name,
            "asn": self.asn,
            "as_org": self.as_org,
            "is_eu": self.is_eu,
            "database_version": self.database_version,
            "collected_at": self.collected_at.isoformat(),
        }


def lookup_geoip(
    ip_str: str,
    db_path: str | None = None,
    allow_fallback: bool = True,
    http_client: httpx.Client | None = None,
) -> GeoIPResult:
    """Lookup geographical location and ASN for an IP address.

    Enforces:
    - Invalid IPs return status="failed", reason_code="invalid_ip".
    - Private/reserved/non-public IPs return status="failed",
      reason_code="private_ip".
    - If no local dataset is available and fallback is disabled,
      status="unlicensed" is returned.
    - If fallback is enabled, ipwho.is is queried synchronously.
    - Successful lookups distinguish between match and no_match.
    """

    clean_ip = ip_str.strip().strip("[]")

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return GeoIPResult(
            ip=ip_str,
            status="failed",
            reason_code="invalid_ip",
            verdict="unknown",
        )

    if not is_ip_public(ip_obj):
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="private_ip",
            verdict="unknown",
        )

    # No local GeoIP reader is currently available.
    # Preserve the previous behaviour unless external fallback
    # was explicitly permitted by the caller.
    if not allow_fallback:
        return GeoIPResult(
            ip=clean_ip,
            status="unlicensed",
            reason_code=(
                "dataset_reader_unavailable"
                if db_path and Path(db_path).is_file()
                else "dataset_not_installed"
            ),
            verdict="unknown",
        )

    url = f"https://ipwho.is/{clean_ip}"

    client = http_client or httpx.Client(timeout=httpx.Timeout(5.0), follow_redirects=False)
    try:
        response = client.get(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "geoip-lookup/1.0",
            },
        )

    except httpx.TimeoutException:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_timeout",
            verdict="unknown",
        )

    except httpx.RequestError:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_unavailable",
            verdict="unknown",
        )
    finally:
        if http_client is None:
            client.close()

    if response.status_code == 429:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_rate_limited",
            verdict="unknown",
        )

    if response.status_code >= 400:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code=f"provider_http_{response.status_code}",
            verdict="unknown",
        )

    try:
        payload = response.json()
    except ValueError:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="invalid_provider_response",
            verdict="unknown",
        )

    if not isinstance(payload, dict):
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="invalid_provider_response",
            verdict="unknown",
        )

    # ipwho.is may return HTTP 200 while indicating an
    # application-level lookup failure.
    if payload.get("success") is not True:
        return GeoIPResult(
            ip=clean_ip,
            status="failed",
            reason_code="provider_lookup_failed",
            verdict="unknown",
        )

    connection = payload.get("connection") or {}

    country_code = payload.get("country_code")
    country_name = payload.get("country")
    city_name = payload.get("city")
    asn = connection.get("asn")
    as_org = connection.get("org")

    has_match = any(
        value is not None
        for value in (
            country_code,
            country_name,
            city_name,
            asn,
            as_org,
        )
    )

    return GeoIPResult(
        ip=clean_ip,
        status="succeeded",
        reason_code=None,
        verdict="match" if has_match else "no_match",
        iso_country_code=country_code,
        country_name=country_name,
        city_name=city_name,
        asn=asn if isinstance(asn, int) else None,
        as_org=as_org if isinstance(as_org, str) else None,
        is_eu=payload.get("is_eu") is True,
        database_version=None,
    )
