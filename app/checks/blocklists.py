"""Blocklists: is a host, or an address it resolves to, on a list of malware, phishing or botnets?

Needs the DNS check. The host name, the names it is an alias for (its CNAME targets) and its
public addresses are looked up in lists that ``flask datasets update`` installed
(``BLOCKLIST_PROVIDERS`` chooses them, ``none`` switches the check off): the abuse.ch URLhaus host
file, the Phishing.Database domains and addresses and the abuse.ch Feodo Tracker botnet list.
Everything happens on this machine: no host name and no address leaves it, and nothing is sent to
the assessed host.

What a listing says and what it does not: somebody reported or measured that the name served
malware or phishing, or that the address answered as a botnet server, and the maintainers kept it;
it does not say what is there today. A name that is not listed says very little, because each list
holds only what its maintainers have seen. An address on a CDN or other shared edge is looked up
too, but a listing of it is marked as shared: it can come from any of the sites behind it, so it is
not held against the host.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.dns import alias_names
from app.service import blocklists
from app.service.geo import hint_for

SOURCE = "blocklists"
MAX_NAMES = 7  # the host and up to six names it is an alias for

DataFactory = Callable[[CheckContext], blocklists.BlocklistLookup]


def _default_data(ctx: CheckContext) -> blocklists.BlocklistLookup:
    directory = ctx.config.get("DATASETS_DIR")
    return blocklists.shared(Path(str(directory))) if directory else blocklists.NOTHING


def names_to_ask(host: str, dns_data: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(name, role) pairs: the host first, then the names it is an alias for. Only exact names:
    a listed parent domain says nothing about the other hosts below it."""
    found = [(host, "host")]
    seen = {host}
    for alias in alias_names(dns_data):
        name = blocklists.normalise_name(alias)
        if name is not None and name not in seen and len(found) < MAX_NAMES:
            seen.add(name)
            found.append((name, "alias"))
    return found


def network_of(
    ip: str, ip_outcome: CheckOutcome | None, aliases: list[str]
) -> Mapping[str, Any] | None:
    """The CDN/cloud hint for ``ip``: the IP check's if it ran, else one from the alias names."""
    if ip_outcome is not None and ip_outcome.status in ("ok", "no_data"):
        for entry in ip_outcome.data.get("addresses", []):
            if entry.get("ip") == ip and entry.get("network"):
                return dict(entry["network"])
    hint = hint_for(None, aliases)
    return hint.to_data() if hint else None


class BlocklistsCheck:
    """Look the host, its aliases and its addresses up in the installed blocklists."""

    key = "blocklists"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)
    after: tuple[str, ...] = ("ip",)

    def __init__(self, data_factory: DataFactory | None = None) -> None:
        self._data = data_factory or _default_data

    def run(self, ctx: CheckContext) -> CheckOutcome:
        host = blocklists.normalise_name(ctx.hostname or "")
        if host is None:
            return CheckOutcome("error", "invalid_name", {"host": (ctx.hostname or "")[:253]})
        enabled = [
            key
            for key in ctx.config.get("BLOCKLIST_PROVIDERS", list(blocklists.PROVIDERS))
            if key in blocklists.PROVIDERS
        ]
        if not enabled:  # the owner's decision, not a failure: no gap and no "partial" scan
            return CheckOutcome("skipped", "disabled", {"host": host})

        dns = ctx.previous.get("dns")
        dns_data: Mapping[str, Any] = dns.data if dns is not None else {}
        found = [str(ip) for ip in dns_data.get("addresses", [])]
        addresses = found[: blocklists.MAX_ADDRESSES]
        canonical = {ip: blocklists.normalise_address(ip) for ip in addresses}
        names = names_to_ask(host, dns_data)

        lists = self._data(ctx)
        snapshot = lists.snapshot(only=enabled)
        listings = (
            lists.lookup(
                [name for name, _ in names],
                [text for text in canonical.values() if text is not None],
                only=enabled,
            )
            if snapshot.feeds
            else blocklists.Listings({}, {})
        )
        unreadable = set(snapshot.unreadable) | set(listings.unreadable)
        broken = [key for key in blocklists.PROVIDERS if key in unreadable]
        consulted = [feed for feed in snapshot.feeds if feed.key not in listings.unreadable]
        data: dict[str, Any] = {
            "host": host,
            "feeds": [feed.to_data() for feed in consulted],
            "not_installed": [
                key
                for key in enabled
                if key not in broken and all(feed.key != key for feed in snapshot.feeds)
            ],
            "unreadable": broken,
        }
        if not consulted:  # nothing to look in: not "not listed"
            reason = "blocklists_unreadable" if broken else "blocklists_missing"
            return CheckOutcome("unavailable", reason, data, SOURCE)

        asked = {feed.key for feed in consulted}
        aliases = [name for name, role in names if role == "alias"]
        ip_outcome = ctx.previous.get("ip")
        rows: list[dict[str, Any]] = []
        for ip in addresses:
            network = network_of(ip, ip_outcome, aliases)
            rows.append(
                {
                    "ip": ip,
                    "listed_on": _listed(listings.addresses, canonical[ip], asked),
                    "network": dict(network) if network else None,
                    "shared": bool(network and network.get("edge")),
                }
            )
        data["names"] = [
            {"name": name, "role": role, "listed_on": _listed(listings.names, name, asked)}
            for name, role in names
        ]
        data["addresses"] = rows
        data["addresses_total"] = len(found)
        data["truncated"] = len(found) > len(addresses)
        return CheckOutcome("ok", data=data, source=f"{SOURCE}:{','.join(sorted(asked))}")


def _listed(found: Mapping[str, tuple[str, ...]], value: str | None, asked: set[str]) -> list[str]:
    """The providers that list ``value``, in the order the providers are defined."""
    keys = found.get(value, ()) if value is not None else ()
    return [key for key in blocklists.PROVIDERS if key in keys and key in asked]
