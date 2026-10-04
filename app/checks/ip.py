"""IP: where a host's addresses are, whose network they belong to, and what their reverse DNS says.

Needs the DNS check: only the public addresses it screened are looked up, in the offline DB-IP
databases (nothing is sent to a third party). The location is where an address is registered or
announced; for CDN and anycast networks that is an edge site, not the data centre, which is why
each address carries a network hint (from its AS number, its CNAME chain and its reverse DNS).
Rules that judge the location must read that hint.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.dns import SHARED_RESOLVERS, reverse_names
from app.service.geo import (
    SHARED_PROVIDERS,
    DatabaseInfo,
    GeoUnavailableError,
    IpLocation,
    hint_for,
)

MAX_ADDRESSES = 8  # per host
MAX_PTR_NAMES = 5  # per address
MAX_NAME = 253
STOP_REVERSE_AFTER = ("timeout", "network_error")  # resolver trouble: do not wait on every address


class GeoProvider(Protocol):
    """What the check needs from a location provider (tests substitute a fake)."""

    def lookup(self, ip: str) -> IpLocation: ...

    def databases(self) -> list[DatabaseInfo]: ...


ProviderFactory = Callable[[Mapping[str, Any]], GeoProvider]
ReverseLookup = Callable[[Mapping[str, Any], str], tuple[list[str], str | None]]


def _default_provider(config: Mapping[str, Any]) -> GeoProvider:
    return SHARED_PROVIDERS.get(Path(str(config["DATASETS_DIR"])))


def _default_reverse(config: Mapping[str, Any], ip: str) -> tuple[list[str], str | None]:
    lifetime = float(config.get("DNS_TIMEOUT_SECONDS", 5.0))
    return reverse_names(SHARED_RESOLVERS.get(config), ip, lifetime)


def _alias_names(dns_data: Mapping[str, Any]) -> list[str]:
    """The names a host is an alias for (its CNAME targets), as CDN hints."""
    targets = [str(step.get("target", "")) for step in dns_data.get("cname", [])]
    canonical = str(dns_data.get("canonical_name", ""))
    return [name for name in (*targets, canonical) if name]


class IpCheck:
    """Locate the public addresses of a host."""

    key = "ip"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(
        self,
        provider_factory: ProviderFactory | None = None,
        reverse_lookup: ReverseLookup | None = None,
    ) -> None:
        self._provider = provider_factory or _default_provider
        self._reverse = reverse_lookup or _default_reverse

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        addresses = [str(ip) for ip in dns.data.get("addresses", [])] if dns else []
        if dns is None or not addresses:
            return CheckOutcome("skipped", "no_public_address", {})
        addresses = addresses[:MAX_ADDRESSES]
        aliases = _alias_names(dns.data)
        provider = self._provider(ctx.config)

        entries: list[dict[str, Any]] = []
        reverse_works = True
        for ip in addresses:
            try:
                location = provider.lookup(ip)
            except GeoUnavailableError as exc:
                return CheckOutcome(
                    "unavailable", exc.reason_code, {"addresses": addresses}, "dbip"
                )
            names: list[str] = []
            error: str | None = None
            if reverse_works:
                names, error = self._reverse(ctx.config, ip)
                reverse_works = error not in STOP_REVERSE_AFTER
            names = [name[:MAX_NAME] for name in names[:MAX_PTR_NAMES]]
            hint = hint_for(location.asn, [*aliases, *names])
            entries.append(
                {
                    "ip": ip,
                    "found": location.found,
                    **location.to_data(),
                    "network": hint.to_data() if hint else None,
                    "ptr": names,
                    "ptr_error": error,
                }
            )

        located = [entry for entry in entries if entry["country"]]
        data: dict[str, Any] = {
            "addresses": entries,
            "countries": sorted({str(entry["country"]) for entry in located}),
            "edge": any(entry["network"] and entry["network"]["edge"] for entry in entries),
            "all_edge": bool(entries)
            and all(entry["network"] and entry["network"]["edge"] for entry in entries),
            "databases": [info.to_data() for info in provider.databases()],
        }
        if any(entry["found"] for entry in entries):
            return CheckOutcome("ok", data=data, source="dbip")
        return CheckOutcome("no_data", "not_in_database", data, "dbip")
