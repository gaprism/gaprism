"""Contract for checks: one module per check, typed outcomes, no framework.

A check receives a ``CheckContext`` and returns a ``CheckOutcome``. It never touches the
database (the engine persists outcomes), and anything it sends to an assessed target must go
through ``runner/`` (the egress gate). Public provider APIs use the shared HTTP client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol

import httpx

from app.config import EXTERNAL_LOOKUP_DEFAULTS

# ok: collected · no_data: asked, nothing there · unavailable: not configured, no key, quota ·
# error: failed · skipped: a prerequisite was not ok, or the owner switched the check off (a
# decision, not a gap: reason ``disabled``). Never show these as "clean".
CheckStatus = Literal["ok", "no_data", "unavailable", "error", "skipped"]
CheckScope = Literal["host", "domain"]


@dataclass(frozen=True)
class CheckOutcome:
    """What a check found, and how it went."""

    status: CheckStatus
    reason_code: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    source: str | None = None


@dataclass(frozen=True)
class CachedAnswer:
    """A provider answer remembered by the cache (only definitive ones: ``ok``, ``no_data``)."""

    status: str
    payload: dict[str, Any]
    fetched_at: datetime


class CacheStore(Protocol):
    """Short-lived storage for provider answers, so re-scans do not repeat calls.

    The engine supplies it (backed by the ``provider_cache`` table); checks never touch the
    database themselves. A broken cache must never break a check: both calls fail soft.
    """

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None: ...

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None: ...


@dataclass(frozen=True)
class CheckContext:
    """Everything a check may use."""

    domain: str
    hostname: str | None
    config: Mapping[str, Any]
    http: httpx.Client
    # Outcomes of the checks in ``needs`` (always ``ok``) and ``after`` (whatever they ended as).
    previous: Mapping[str, CheckOutcome] = field(default_factory=dict)
    cache: CacheStore | None = None


class Check(Protocol):
    """One technical check.

    ``scope`` is ``host`` (runs for every host) or ``domain`` (runs once per scan). ``needs``
    names checks that must be ``ok`` for the same subject first; otherwise this one is skipped.

    A check may also declare ``after`` (optional): checks whose outcome it can use when there is
    one, whatever it was. It waits for them to finish but runs regardless, e.g. the ports check
    reads the IP check's CDN hint but does not depend on the location databases being installed.
    """

    key: str
    scope: CheckScope
    needs: tuple[str, ...]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        """Run the check; raise only for programming errors."""
        ...


def lookup_enabled(config: Mapping[str, Any], name: str) -> bool:
    """May the domain be looked up at this third party (``EXTERNAL_DOMAIN_LOOKUPS``)? A
    configuration that does not say has the default ones on, and the opt-in ones off."""
    return name in config.get("EXTERNAL_DOMAIN_LOOKUPS", EXTERNAL_LOOKUP_DEFAULTS)


def waits_for(check: Check) -> tuple[str, ...]:
    """The checks that must have finished before ``check`` starts: ``needs`` plus ``after``."""
    soft: tuple[str, ...] = getattr(check, "after", ())
    return (*check.needs, *soft)
