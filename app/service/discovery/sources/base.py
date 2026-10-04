"""Contract shared by all Certificate Transparency discovery sources, and their HTTP helper.

Sources talk to fixed, public provider APIs (not to the assessed targets, so this is not the
egress gate's job). They never raise for provider trouble: every problem becomes a typed
``SourceOutcome`` so that "the source failed" is never mistaken for "nothing was found".
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx

SourceStatus = Literal["ok", "unavailable", "error"]

# Responses above this size are refused instead of being truncated into "success".
DEFAULT_MAX_RESPONSE_BYTES = 25 * 1024 * 1024
RETRYABLE_STATUSES = frozenset({502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 5.0
_NEXT_LINK = re.compile(r'<([^>]*)>\s*;[^,]*\brel="?next"?', re.IGNORECASE)


@dataclass(frozen=True)
class DiscoveredName:
    """One certificate name as reported by a source (lower-case, may be a ``*.`` wildcard)."""

    name: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass(frozen=True)
class SourceOutcome:
    """Everything one source reported for one domain, including how it went."""

    source: str
    status: SourceStatus
    reason_code: str | None = None
    names: tuple[DiscoveredName, ...] = ()
    pages: int = 0
    truncated: bool = False
    duration_ms: int = 0

    def summary(self) -> dict[str, Any]:
        """JSON-serialisable record without the names (those are merged, not stored per source)."""
        return {
            "source": self.source,
            "status": self.status,
            "reason_code": self.reason_code,
            "names": len({name.name for name in self.names}),
            "pages": self.pages,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
        }


class DiscoverySource(Protocol):
    """A provider of certificate names for a domain."""

    key: str

    def fetch(self, domain: str) -> SourceOutcome:
        """Return every name the provider knows below ``domain``; never raises for provider
        problems."""
        ...


class SourceError(Exception):
    """Internal: a provider problem with its classification. Messages carry no URLs or keys."""

    def __init__(
        self, status: SourceStatus, reason_code: str, http_status: int | None = None
    ) -> None:
        super().__init__(reason_code)
        self.status: SourceStatus = status
        self.reason_code = reason_code
        self.http_status = http_status


@dataclass(frozen=True)
class FetchPolicy:
    """Retry and size limits for provider requests."""

    attempts: int = 2
    base_delay: float = 1.0
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    sleep: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class ProviderResponse:
    """A fully read, size-checked successful (HTTP 200) provider response."""

    headers: httpx.Headers
    content: bytes

    def json(self) -> Any:
        """Decode the body; a body that is not JSON is a provider error, not "no data"."""
        try:
            return json.loads(self.content)
        except ValueError:
            raise SourceError("error", "invalid_response") from None

    def next_link(self) -> str | None:
        """Target of an RFC 8288 ``Link: <...>; rel="next"`` header, if there is one."""
        for header in self.headers.get_list("link"):
            match = _NEXT_LINK.search(header)
            if match:
                return match.group(1)
        return None


def parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp (a missing offset means UTC); ``None`` if absent or invalid."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _backoff(policy: FetchPolicy, attempt: int) -> float:
    return float(min(8.0, policy.base_delay * 2**attempt) * random.uniform(0.5, 1.0))  # noqa: S311


def _classify(status: int, authenticated: bool) -> SourceError:
    if status == 429:
        return SourceError("unavailable", "rate_limited", status)
    if status == 401:
        return SourceError("unavailable", "invalid_key" if authenticated else "forbidden", status)
    if status == 403:
        return SourceError("unavailable", "forbidden", status)
    return SourceError("error", f"http_{status}", status)


def fetch_response(
    client: httpx.Client,
    url: str,
    *,
    params: Mapping[str, str | int] | None = None,
    headers: Mapping[str, str] | None = None,
    policy: FetchPolicy | None = None,
    authenticated: bool = False,
) -> ProviderResponse:
    """GET ``url`` with bounded retries and a bounded body; raise ``SourceError`` on failure.

    Retries timeouts, connection errors and 502/503/504 with jittered exponential backoff, and
    honours a short ``Retry-After`` on 429 once. Everything else fails immediately.
    """
    policy = policy or FetchPolicy()
    last: SourceError | None = None
    already_waited = False  # a server-requested Retry-After replaces the generic backoff
    for attempt in range(policy.attempts):
        if attempt and not already_waited:
            policy.sleep(_backoff(policy, attempt - 1))
        already_waited = False
        try:
            with client.stream("GET", url, params=params, headers=headers) as response:
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > policy.max_bytes:
                        raise SourceError("error", "response_too_large", response.status_code)
                    chunks.append(chunk)
                status = response.status_code
                retry_after = response.headers.get("Retry-After")
                result = ProviderResponse(headers=response.headers, content=b"".join(chunks))
        except SourceError:
            raise
        except httpx.TimeoutException:
            last = SourceError("error", "timeout")
            continue
        except httpx.TransportError:
            last = SourceError("error", "connection_failed")
            continue

        if status == 200:
            return result
        problem = _classify(status, authenticated)
        if status == 429 and retry_after and attempt + 1 < policy.attempts:
            try:
                wait = float(retry_after)
            except ValueError:
                wait = MAX_RETRY_AFTER_SECONDS + 1
            if wait <= MAX_RETRY_AFTER_SECONDS:
                policy.sleep(wait)
                already_waited = True
                last = problem
                continue
        if status in RETRYABLE_STATUSES:
            last = problem
            continue
        raise problem
    raise last or SourceError("error", "unknown")
