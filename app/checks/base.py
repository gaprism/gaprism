"""Contract for checks: one module per check, typed outcomes, no framework.

A check receives a ``CheckContext`` and returns a ``CheckOutcome``. It never touches the
database (the engine persists outcomes), and anything it sends to an assessed target must go
through ``runner/`` (the egress gate). Public provider APIs use the shared HTTP client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

import httpx

# ok: collected · no_data: asked, nothing there · unavailable: not configured, no key, quota,
# disabled · error: failed · skipped: a prerequisite was not ok. Never show these as "clean".
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
class CheckContext:
    """Everything a check may use."""

    domain: str
    hostname: str | None
    config: Mapping[str, Any]
    http: httpx.Client
    previous: Mapping[str, CheckOutcome] = field(default_factory=dict)  # outcomes of ``needs``


class Check(Protocol):
    """One technical check.

    ``scope`` is ``host`` (runs for every host) or ``domain`` (runs once per scan). ``needs``
    names checks that must be ``ok`` for the same subject first; otherwise this one is skipped.
    """

    key: str
    scope: CheckScope
    needs: tuple[str, ...]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        """Run the check; raise only for programming errors."""
        ...
