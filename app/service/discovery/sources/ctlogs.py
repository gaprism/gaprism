"""ctlogs.dev: one row per hostname, paged with an opaque cursor (``?after=``).

Free and keyless callers may page ten pages deep; a key (``Authorization: Bearer``) lifts that
within its quota. Rows come with live DNS hints (``dns``, ``a``); they are ignored here because
our own DNS check decides what resolves.
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

PAGE_SIZE = 100


def _invalid() -> SourceError:
    return SourceError("error", "invalid_response")


def parse_hosts_page(payload: Any) -> tuple[list[DiscoveredName], str]:
    """Validate one ``/v1/hosts`` page strictly; return its names and the next cursor ("" = last).

    A payload that does not match the documented envelope is a provider error: it must never be
    mistaken for an empty (successful) result.
    """
    if not isinstance(payload, dict):
        raise _invalid()
    hosts = payload.get("hosts")
    has_next = payload.get("has_next")
    cursor = payload.get("next_cursor") or ""
    if (
        not isinstance(hosts, list)
        or not isinstance(has_next, bool)
        or not isinstance(cursor, str)
        or has_next != bool(cursor)
    ):
        raise _invalid()

    names: list[DiscoveredName] = []
    for row in hosts:
        if not isinstance(row, dict):
            raise _invalid()
        host = row.get("host")
        certs = row.get("certs")
        if not isinstance(host, str) or not host.strip() or type(certs) is not int or certs < 1:
            raise _invalid()
        first_seen = parse_timestamp(row.get("first_seen"))
        last_seen = parse_timestamp(row.get("last_seen"))
        for field, parsed in (("first_seen", first_seen), ("last_seen", last_seen)):
            if row.get(field) is not None and parsed is None:
                raise _invalid()
        names.append(DiscoveredName(host.strip().lower(), first_seen, last_seen))
    return names, cursor


class CtlogsSource:
    """Discovery through the ctlogs.dev ``/v1/hosts/{domain}`` endpoint."""

    key = "ctlogs"

    def __init__(
        self,
        client: httpx.Client,
        *,
        api_key: str = "",
        max_pages: int = 50,
        base_url: str = "https://api.ctlogs.dev",
        policy: FetchPolicy | None = None,
    ) -> None:
        self._client = client
        self._api_key = api_key
        self._max_pages = max_pages
        self._base_url = base_url.rstrip("/")
        self._policy = policy or FetchPolicy(attempts=2)

    def fetch(self, domain: str) -> SourceOutcome:
        started = time.monotonic()
        names: list[DiscoveredName] = []
        pages = 0
        truncated = False
        cursor = ""
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        try:
            while True:
                if pages >= self._max_pages:
                    truncated = True
                    break
                params: dict[str, str | int] = {"limit": PAGE_SIZE}
                if cursor:
                    params["after"] = cursor
                try:
                    response = fetch_response(
                        self._client,
                        f"{self._base_url}/v1/hosts/{domain}",
                        params=params,
                        headers=headers,
                        policy=self._policy,
                        authenticated=bool(self._api_key),
                    )
                except SourceError as problem:
                    if problem.http_status == 403 and pages > 0:
                        # Keyless callers may only page ten deep: keep what we have and say so.
                        truncated = True
                        break
                    raise
                page_names, cursor = parse_hosts_page(response.json())
                names.extend(page_names)
                pages += 1
                if not cursor:
                    break
        except SourceError as problem:
            return SourceOutcome(
                self.key,
                problem.status,
                problem.reason_code,
                tuple(names),
                pages,
                truncated=bool(names),  # partial data is better than none, but flagged as partial
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
