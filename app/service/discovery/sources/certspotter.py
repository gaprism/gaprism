"""CertSpotter (SSLMate) CT search API v1: one row per issued certificate.

Unauthenticated use is allowed but rate limited ("a limited number of queries per hour" per the
provider); a token (``Authorization: Bearer``) raises the limit. Pages follow ``after=<last id>``
and announce the next page with a ``Link: <...>; rel="next"`` header.
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


def _invalid() -> SourceError:
    return SourceError("error", "invalid_response")


def parse_issuances(payload: Any) -> tuple[list[DiscoveredName], str | None]:
    """Validate one issuance list; return its names and the id of the last issuance.

    Certificates routinely name unrelated domains too; scope filtering happens later.
    """
    if not isinstance(payload, list):
        raise _invalid()
    names: list[DiscoveredName] = []
    last_id: str | None = None
    for item in payload:
        if not isinstance(item, dict):
            raise _invalid()
        identifier = item.get("id")
        dns_names = item.get("dns_names")
        if not isinstance(identifier, str | int) or not isinstance(dns_names, list):
            raise _invalid()
        issued = parse_timestamp(item.get("not_before"))
        for name in dns_names:
            if not isinstance(name, str):
                raise _invalid()
            if name.strip():
                names.append(DiscoveredName(name.strip().lower(), issued, issued))
        last_id = str(identifier)
    return names, last_id


class CertSpotterSource:
    """Discovery through ``/v1/issuances?include_subdomains=true&expand=dns_names``."""

    key = "certspotter"

    def __init__(
        self,
        client: httpx.Client,
        *,
        token: str = "",
        max_pages: int = 50,
        base_url: str = "https://api.certspotter.com",
        policy: FetchPolicy | None = None,
    ) -> None:
        self._client = client
        self._token = token
        self._max_pages = max_pages
        self._base_url = base_url.rstrip("/")
        self._policy = policy or FetchPolicy(attempts=2)

    def fetch(self, domain: str) -> SourceOutcome:
        started = time.monotonic()
        names: list[DiscoveredName] = []
        pages = 0
        truncated = False
        after: str | None = None
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        try:
            while True:
                if pages >= self._max_pages:
                    truncated = True
                    break
                params: dict[str, str | int] = {
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }
                if after:
                    params["after"] = after
                response = fetch_response(
                    self._client,
                    f"{self._base_url}/v1/issuances",
                    params=params,
                    headers=headers,
                    policy=self._policy,
                    authenticated=bool(self._token),
                )
                page_names, last_id = parse_issuances(response.json())
                if last_id is None:
                    break  # an empty page ends the listing
                if last_id == after:
                    raise SourceError("error", "pagination_stalled")
                names.extend(page_names)
                pages += 1
                after = last_id
                if response.next_link() is None:
                    break
        except SourceError as problem:
            return SourceOutcome(
                self.key,
                problem.status,
                problem.reason_code,
                tuple(names),
                pages,
                truncated=bool(names),
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return SourceOutcome(
            self.key,
            "ok",
            None,
            tuple(names),
            pages,
            truncated,
            int((time.monotonic() - started) * 1000),
        )
