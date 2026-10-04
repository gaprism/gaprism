"""crt.sh: free, keyless and community run, therefore often overloaded (502, timeouts).

The whole answer comes in one response (``%.domain`` matches the domain and everything below
it), so there is no paging; the request is retried with jittered backoff and the body is size
bounded.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.service.discovery.sources.base import (
    DiscoveredName,
    FetchPolicy,
    SourceError,
    SourceOutcome,
    fetch_response,
    parse_timestamp,
)


def parse_certificates(payload: Any) -> list[DiscoveredName]:
    """Validate crt.sh's JSON list; ``name_value`` holds newline-separated names."""
    if not isinstance(payload, list):
        raise SourceError("error", "invalid_response")
    names: list[DiscoveredName] = []
    for row in payload:
        if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
            raise SourceError("error", "invalid_response")
        issued = parse_timestamp(row.get("not_before"))
        for name in row["name_value"].splitlines():
            if name.strip():
                names.append(DiscoveredName(name.strip().lower(), issued, issued))
    return names


class CrtShSource:
    """Discovery through ``https://crt.sh/?q=%.domain&output=json``."""

    key = "crtsh"

    def __init__(
        self,
        client: httpx.Client,
        *,
        base_url: str = "https://crt.sh",
        policy: FetchPolicy | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._policy = policy or FetchPolicy(attempts=3)

    def fetch(self, domain: str) -> SourceOutcome:
        started = time.monotonic()
        try:
            response = fetch_response(
                self._client,
                f"{self._base_url}/",
                params={"q": f"%.{domain}", "output": "json"},
                policy=self._policy,
            )
            names = parse_certificates(response.json())
        except SourceError as problem:
            return SourceOutcome(
                self.key,
                problem.status,
                problem.reason_code,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return SourceOutcome(
            self.key,
            "ok",
            None,
            tuple(names),
            pages=1,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
