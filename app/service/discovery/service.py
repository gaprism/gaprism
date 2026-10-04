"""Merge the names reported by CT sources into the host list of a scan.

Rules (from the project principles): a CT name is not a live host, and a wildcard is a pattern,
never a host. Names outside the assessed domain (certificates list unrelated SANs all the time)
are counted and excluded, and everything the sources could not tell us stays visible.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from app.service.discovery.scope import DomainScope, is_in_scope
from app.service.discovery.sources.base import DiscoverySource, SourceOutcome

DiscoveryMode = Literal["union", "first"]

log = logging.getLogger(__name__)

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


@dataclass(frozen=True)
class DiscoveredHost:
    """A concrete, in-scope hostname and which sources reported it."""

    hostname: str
    first_seen: datetime | None
    last_seen: datetime | None
    sources: tuple[str, ...]

    def to_data(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "sources": list(self.sources),
        }


@dataclass(frozen=True)
class DiscoveryResult:
    """The merged outcome of all sources."""

    hosts: tuple[DiscoveredHost, ...]
    wildcard_patterns: tuple[str, ...]
    names_seen: int
    out_of_scope: int
    invalid_names: int
    dropped_by_cap: int
    outcomes: tuple[SourceOutcome, ...]

    @property
    def sources_ok(self) -> int:
        """How many sources answered successfully."""
        return sum(1 for outcome in self.outcomes if outcome.status == "ok")

    def to_data(self) -> dict[str, Any]:
        """JSON stored with the discovery check result."""
        return {
            "hosts": [host.to_data() for host in self.hosts],
            "wildcard_patterns": list(self.wildcard_patterns),
            "counts": {
                "names_seen": self.names_seen,
                "hosts": len(self.hosts),
                "out_of_scope": self.out_of_scope,
                "invalid": self.invalid_names,
                "dropped_by_cap": self.dropped_by_cap,
            },
            "sources": [outcome.summary() for outcome in self.outcomes],
        }


def normalise_name(raw: str) -> tuple[str, bool] | None:
    """Return ``(hostname, is_wildcard)`` in lower-case ASCII, or ``None`` if not a hostname."""
    name = raw.strip().lower().rstrip(".")
    if not name or len(name) > 253:
        return None
    wildcard = name.startswith("*.")
    if wildcard:
        name = name[2:]
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    return name, wildcard


class _Accumulator:
    def __init__(self, hostname: str) -> None:
        self.hostname = hostname
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.sources: set[str] = set()

    def add(self, source: str, first_seen: datetime | None, last_seen: datetime | None) -> None:
        self.sources.add(source)
        if first_seen and (self.first_seen is None or first_seen < self.first_seen):
            self.first_seen = first_seen
        if last_seen and (self.last_seen is None or last_seen > self.last_seen):
            self.last_seen = last_seen


def merge_outcomes(
    scope: DomainScope, outcomes: Sequence[SourceOutcome], *, max_hosts: int
) -> DiscoveryResult:
    """Deduplicate, scope-filter and cap the names of all outcomes.

    Names from sources that failed half-way still count (partial data is flagged on the
    outcome). When more than ``max_hosts`` remain, the apex comes first, then the most recently
    seen names; the rest is counted in ``dropped_by_cap``.
    """
    merged: dict[str, _Accumulator] = {}
    wildcards: set[str] = set()
    out_of_scope: set[str] = set()
    invalid: set[str] = set()
    seen: set[str] = set()

    for outcome in outcomes:
        for item in outcome.names:
            parsed = normalise_name(item.name)
            if parsed is None:
                invalid.add(item.name)
                continue
            name, wildcard = parsed
            seen.add(f"*.{name}" if wildcard else name)
            if not is_in_scope(name, scope):
                out_of_scope.add(f"*.{name}" if wildcard else name)
            elif wildcard:
                wildcards.add(f"*.{name}")
            else:
                merged.setdefault(name, _Accumulator(name)).add(
                    outcome.source, item.first_seen, item.last_seen
                )

    def order(acc: _Accumulator) -> tuple[int, float, str]:
        recency = -acc.last_seen.timestamp() if acc.last_seen else float("inf")
        return (0 if acc.hostname == scope.canonical else 1, recency, acc.hostname)

    ordered = sorted(merged.values(), key=order)
    kept = ordered[:max_hosts]
    return DiscoveryResult(
        hosts=tuple(
            DiscoveredHost(acc.hostname, acc.first_seen, acc.last_seen, tuple(sorted(acc.sources)))
            for acc in kept
        ),
        wildcard_patterns=tuple(sorted(wildcards)),
        names_seen=len(seen),
        out_of_scope=len(out_of_scope),
        invalid_names=len(invalid),
        dropped_by_cap=len(ordered) - len(kept),
        outcomes=tuple(outcomes),
    )


DEFAULT_BUDGET_SECONDS = 45.0


def _fetch_safely(source: DiscoverySource, domain: str) -> SourceOutcome:
    """Ask one source. Adapters report provider trouble themselves; this catches their bugs."""
    started = time.monotonic()
    try:
        return source.fetch(domain)
    except Exception:
        log.exception("CT source %s crashed for %s", source.key, domain)
        return SourceOutcome(
            source.key,
            "error",
            "internal_error",
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def _fetch_in_parallel(
    domain: str, sources: Sequence[DiscoverySource], budget_seconds: float
) -> list[SourceOutcome]:
    """Ask all sources at once; one that exceeds the shared time budget is reported, not awaited.

    A straggler thread is left to finish on its own: every adapter bounds its own retries and
    timeouts, so it ends soon, and its late answer is ignored.
    """
    pool = ThreadPoolExecutor(max_workers=len(sources), thread_name_prefix="ct-source")
    try:
        futures = [pool.submit(_fetch_safely, source, domain) for source in sources]
        deadline = time.monotonic() + budget_seconds
        outcomes: list[SourceOutcome] = []
        for source, future in zip(sources, futures, strict=True):
            try:
                outcomes.append(future.result(timeout=max(0.0, deadline - time.monotonic())))
            except TimeoutError:
                outcomes.append(
                    SourceOutcome(
                        source.key,
                        "error",
                        "budget_exceeded",
                        duration_ms=int(budget_seconds * 1000),
                    )
                )
        return outcomes
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def run_discovery(
    scope: DomainScope,
    sources: Sequence[DiscoverySource],
    *,
    mode: DiscoveryMode = "union",
    max_hosts: int = 200,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
) -> DiscoveryResult:
    """Ask the sources about ``scope`` and merge the answers.

    ``union`` asks every source at the same time (best coverage; a failing or slow source never
    fails the discovery, it just reports why); ``first`` asks them in order and stops after the
    first one that answered successfully (saves provider quota).
    """
    if mode == "union" and len(sources) > 1:
        outcomes = _fetch_in_parallel(scope.canonical, sources, budget_seconds)
    else:
        outcomes = []
        for source in sources:
            outcome = _fetch_safely(source, scope.canonical)
            outcomes.append(outcome)
            if mode == "first" and outcome.status == "ok":
                break
    return merge_outcomes(scope, outcomes, max_hosts=max_hosts)
