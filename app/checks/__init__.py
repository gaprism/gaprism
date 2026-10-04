"""Registry of checks. Adding a check = one module, one test, one row in docs/checks-catalog.md."""

from __future__ import annotations

from collections.abc import Mapping

from app.checks.base import Check, CheckContext, CheckOutcome, CheckScope, CheckStatus
from app.checks.discovery import DiscoveryCheck

REGISTRY: dict[str, Check] = {check.key: check for check in (DiscoveryCheck(),)}

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
    "Check",
    "CheckContext",
    "CheckOutcome",
    "CheckScope",
    "CheckStatus",
    "checks_with_scope",
]
