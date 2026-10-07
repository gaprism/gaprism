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
    lookup_enabled,
    waits_for,
)
from app.checks.breaches import BreachesCheck
from app.checks.discovery import DiscoveryCheck
from app.checks.dns import DnsCheck
from app.checks.domain_dns import DomainDnsCheck
from app.checks.email import EmailCheck
from app.checks.hsts_preload import HstsPreloadCheck
from app.checks.http import HttpCheck
from app.checks.ip import IpCheck
from app.checks.ports import PortsCheck
from app.checks.registration import RegistrationCheck
from app.checks.securitytxt import SecurityTxtCheck
from app.checks.takeover import TakeoverCheck
from app.checks.tls import TlsCheck
from app.checks.tls_protocols import TlsProtocolsCheck

REGISTRY: dict[str, Check] = {
    check.key: check
    for check in (
        DiscoveryCheck(),
        DnsCheck(),
        IpCheck(),
        PortsCheck(),
        TlsCheck(),
        TlsProtocolsCheck(),
        HttpCheck(),
        TakeoverCheck(),
        EmailCheck(),
        RegistrationCheck(),
        DomainDnsCheck(),
        SecurityTxtCheck(),
        HstsPreloadCheck(),
        BreachesCheck(),
    )
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
    "lookup_enabled",
    "waits_for",
]
