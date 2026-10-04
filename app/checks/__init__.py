"""Registry of checks. Adding a check = one module, one test, one row in docs/checks-catalog.md."""

from __future__ import annotations

from collections.abc import Mapping

from app.checks.base import (
    CachedAnswer,
    CacheStore,
    Check,
    CheckContext,
    CheckOutcome,
    CheckScope,
    CheckStatus,
    waits_for,
)
from app.checks.discovery import DiscoveryCheck
from app.checks.dns import DnsCheck
from app.checks.http import HttpCheck
from app.checks.ip import IpCheck
from app.checks.ports import PortsCheck
from app.checks.tls import TlsCheck

REGISTRY: dict[str, Check] = {
    check.key: check
    for check in (DiscoveryCheck(), DnsCheck(), IpCheck(), PortsCheck(), TlsCheck(), HttpCheck())
}

# Discovery is the engine's first stage: it creates the hosts the other checks run for.
DISCOVERY_KEY = "discovery"


def checks_with_scope(
    scope: CheckScope, registry: Mapping[str, Check] | None = None
) -> list[Check]:
    """Registered checks of one scope, in registration order."""
    chosen = REGISTRY if registry is None else registry
    return [check for check in chosen.values() if check.scope == scope]


__all__ = [
    "DISCOVERY_KEY",
    "REGISTRY",
    "CacheStore",
    "CachedAnswer",
    "Check",
    "CheckContext",
    "CheckOutcome",
    "CheckScope",
    "CheckStatus",
    "checks_with_scope",
    "waits_for",
]
