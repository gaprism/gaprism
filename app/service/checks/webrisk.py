"""Google Web Risk URL reputation check adapter with explicit outcome classification."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

import httpx

WEBRISK_SCHEMA_VERSION = 1
WEBRISK_ADAPTER_VERSION = "webrisk-v1"


@dataclass(frozen=True)
class WebRiskThreat:
    """Individual threat detected for a queried URI."""

    threat_type: str  # 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'
    expire_time: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert threat to dictionary."""
        return {
            "threat_type": self.threat_type,
            "expire_time": self.expire_time,
        }


@dataclass(frozen=True)
class WebRiskResult:
    """Immutable result of a Web Risk URI reputation check."""

    url: str
    status: str  # 'succeeded', 'unlicensed', 'failed'
    reason_code: str | None  # Diagnostic code on failure
    verdict: str  # 'match', 'no_match', 'unknown'
    threats: list[WebRiskThreat] = field(default_factory=list)
    collected_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "url": self.url,
            "status": self.status,
            "reason_code": self.reason_code,
            "verdict": self.verdict,
            "threats": [t.to_dict() for t in self.threats],
            "collected_at": self.collected_at.isoformat(),
        }


def lookup_threat_uri(
    url: str,
    api_key: str | None = None,
    http_client: httpx.Client | None = None,
    timeout: float = 10.0,
) -> WebRiskResult:
    """Query Google Web Risk API for URL threat intelligence.

    Enforces:
    - Diagnostic outcome separation (PRV-01):
      - Clean / empty result -> status="succeeded", verdict="no_match"
      - Threat found -> status="succeeded", verdict="match"
      - Missing API key -> status="unlicensed", reason_code="missing_api_key"
      - 429 -> status="failed", reason_code="quota_exhausted"
      - 401/403 -> status="failed", reason_code="auth_failed"
      - Timeout -> status="failed", reason_code="timeout"
    """
    clean_url = url.strip()
    if not api_key:
        return WebRiskResult(
            url=clean_url,
            status="unlicensed",
            reason_code="missing_api_key",
            verdict="unknown",
        )

    endpoint = "https://webrisk.googleapis.com/v1/uris:search"
    params = {
        "key": api_key,
        "uri": clean_url,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
    }

    client = http_client or httpx.Client(timeout=timeout)
    should_close_client = http_client is None

    try:
        response = client.get(endpoint, params=params)
    except httpx.TimeoutException:
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="timeout",
            verdict="unknown",
        )
    except httpx.RequestError:
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )
    finally:
        if should_close_client:
            client.close()

    # 1. 401 / 403 Authentication error
    if response.status_code in (401, 403):
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="auth_failed",
            verdict="unknown",
        )

    # 2. 429 Quota / Rate limit exceeded
    if response.status_code == 429:
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="quota_exhausted",
            verdict="unknown",
        )

    # 3. Non-200 responses
    if response.status_code != 200:
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )

    # 4. Parse 200 OK response
    try:
        payload = response.json()
    except Exception:
        return WebRiskResult(
            url=clean_url,
            status="failed",
            reason_code="provider_error",
            verdict="unknown",
        )

    threat_obj = payload.get("threat")
    if not threat_obj:
        return WebRiskResult(
            url=clean_url,
            status="succeeded",
            reason_code=None,
            verdict="no_match",
            threats=[],
        )

    threat_types = threat_obj.get("threatTypes", [])
    expire_time = threat_obj.get("expireTime")

    threats = [WebRiskThreat(threat_type=str(tt), expire_time=expire_time) for tt in threat_types]

    return WebRiskResult(
        url=clean_url,
        status="succeeded",
        reason_code=None,
        verdict="match" if threats else "no_match",
        threats=threats,
    )
