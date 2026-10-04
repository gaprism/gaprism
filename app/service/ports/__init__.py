"""Open ports, services and CVEs as observed by Shodan or Shodan InternetDB."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from app.service.ports.internetdb import InternetDbProvider
from app.service.ports.models import (
    PortFacts,
    PortService,
    PortsLookup,
    Vulnerability,
)
from app.service.ports.shodan import ShodanProvider
from app.service.ratelimit import LIMITERS


class PortsProvider(Protocol):
    name: str

    def lookup(self, ip: str) -> PortsLookup: ...


def build_provider(config: Mapping[str, Any], client: httpx.Client) -> PortsProvider | str:
    """The provider the configuration asks for, or the reason there is none.

    ``auto`` uses the Shodan host API when a key is configured and the keyless InternetDB
    otherwise. The returned string is a reason code (``disabled``, ``missing_api_key``).
    """
    choice = str(config.get("PORTS_PROVIDER", "auto"))
    key = str(config.get("SHODAN_API_KEY", "") or "")
    if choice == "off":
        return "disabled"
    if choice == "shodan" or (choice == "auto" and key):
        if not key:
            return "missing_api_key"
        rate = float(config.get("SHODAN_RATE_PER_SECOND", 1.0))
        return ShodanProvider(client, key, LIMITERS.get("shodan", rate))
    rate = float(config.get("INTERNETDB_RATE_PER_SECOND", 2.0))
    return InternetDbProvider(client, LIMITERS.get("internetdb", rate))


__all__ = [
    "InternetDbProvider",
    "PortFacts",
    "PortService",
    "PortsLookup",
    "PortsProvider",
    "ShodanProvider",
    "Vulnerability",
    "build_provider",
]
