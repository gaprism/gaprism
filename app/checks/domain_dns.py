"""The domain's DNS set-up: how many name servers it has, how independent they are, and its CAA.

A domain-level check. Everything is read through the configured resolvers. **Name servers** are
asked for the registrable domain (the zone), each one's addresses are looked up, and the check
reports how many servers there are, how many *operators* (the registrable domain of a server's
name: ``nsone.net``, ``awsdns-32.org``) and how many networks (an IPv4 /24 or IPv6 /48 each)
they span. One network (or one server) is a single point of failure; one operator is only a
concentration to be aware of, as the large DNS providers are redundant by design.

**CAA** records say which certificate authorities may issue for the domain; as RFC 8659 prescribes,
the closest name that has any decides, so the tree is climbed from the assessed name up to the zone.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from typing import Any

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.dns import (
    SHARED_RESOLVERS,
    Lookup,
    ResolverCache,
    ResolverLike,
    lookup_addresses,
    lookup_records,
)
from app.service.discovery.psl import registrable_domain

MAX_SERVERS = 8
MAX_ADDRESSES = 4
MAX_RECORDS = 20
MAX_VALUE = 200


def _network(ip: str) -> str | None:
    """The /24 (IPv4) or /48 (IPv6) an address is in, as text."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _operator(host: str) -> str:
    return registrable_domain(host) or host


def caa_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Issuers and reporting addresses out of CAA records (``issue ";"`` forbids everyone)."""
    issuers: list[str] = []
    wildcard: list[str] = []
    reports: list[str] = []
    for record in records:
        tag = str(record.get("tag", "")).lower()
        value = str(record.get("value", ""))
        authority = value.split(";", 1)[0].strip().lower()[:MAX_VALUE]
        if tag == "issue" and authority:
            issuers.append(authority)
        elif tag == "issuewild" and authority:
            wildcard.append(authority)
        elif tag == "iodef" and value.strip():
            reports.append(value.strip()[:MAX_VALUE])
    forbids = (
        any(
            str(r.get("tag", "")).lower() == "issue"
            and not str(r.get("value", "")).split(";")[0].strip()
            for r in records
        )
        and not issuers
    )
    return {
        "issuers": sorted(set(issuers)),
        "issuewild": sorted(set(wildcard)),
        "iodef": reports[:5],
        "forbids_issuance": forbids,
    }


class DomainDnsCheck:
    """Name-server redundancy and CAA of the domain."""

    key = "domain_dns"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def __init__(
        self, resolver_factory: Callable[[Mapping[str, Any]], ResolverLike] | None = None
    ) -> None:
        self._resolvers = (
            SHARED_RESOLVERS if resolver_factory is None else ResolverCache(resolver_factory)
        )

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = ctx.domain.lower().rstrip(".")
        zone = registrable_domain(domain) or domain
        resolver = self._resolvers.get(ctx.config)
        lifetime = float(ctx.config.get("DNS_TIMEOUT_SECONDS", 5.0))
        servers = [str(s) for s in ctx.config.get("EGRESS_DNS_RESOLVERS", [])]
        source = ("dns:" + (",".join(servers) if servers else "system"))[:64]

        ns = lookup_records(resolver, zone, "NS", lifetime)
        if ns.nxdomain:
            return CheckOutcome("no_data", "nxdomain", {"domain": domain, "zone": zone}, source)
        caa = self._caa(resolver, domain, zone, lifetime)
        if ns.error and caa.get("error"):
            return CheckOutcome("error", ns.error, {"domain": domain, "zone": zone}, source)
        data = {
            "domain": domain,
            "zone": zone,
            "ns": self._ns(resolver, ns, lifetime),
            "caa": caa,
        }
        return CheckOutcome("ok", data=data, source=source)

    @staticmethod
    def _ns(resolver: ResolverLike, lookup: Lookup, lifetime: float) -> dict[str, Any]:
        if lookup.error:
            return {"found": None, "error": lookup.error}
        hosts = sorted({str(r["host"]) for r in lookup.records})
        if not hosts:
            return {"found": False}
        rows: list[dict[str, Any]] = []
        for host in hosts[:MAX_SERVERS]:
            addresses = lookup_addresses(resolver, host, lifetime)[:MAX_ADDRESSES]
            rows.append({"host": host, "operator": _operator(host), "addresses": addresses})
        operators = sorted({row["operator"] for row in rows})
        networks = sorted(
            {n for row in rows for ip in row["addresses"] if (n := _network(ip)) is not None}
        )
        problems: list[str] = []  # real weaknesses; one operator alone is only a note
        if len(hosts) < 2:
            problems.append("too_few")
        if any(not row["addresses"] for row in rows):
            problems.append("unresolvable")
        if networks and len(networks) < 2 and len(hosts) >= 2:
            problems.append("single_network")
        return {
            "found": True,
            "count": len(hosts),
            "servers": rows,
            "operators": operators,
            "single_operator": len(hosts) >= 2 and len(operators) < 2,
            "networks": networks,
            "problems": problems,
        }

    @staticmethod
    def _caa(resolver: ResolverLike, domain: str, zone: str, lifetime: float) -> dict[str, Any]:
        """The CAA records that apply: those of the closest name, from ``domain`` up to ``zone``."""
        labels = domain.split(".")
        names = [".".join(labels[i:]) for i in range(len(labels))]
        names = [name for name in names if name == zone or name.endswith("." + zone)] or [domain]
        for name in names:
            lookup = lookup_records(resolver, name, "CAA", lifetime)
            if lookup.error:  # the closer name may have its own: do not guess from a higher one
                return {"found": None, "error": lookup.error}
            if lookup.records:
                records = [
                    {"flags": r["flags"], "tag": r["tag"], "value": r["value"][:MAX_VALUE]}
                    for r in lookup.records[:MAX_RECORDS]
                ]
                return {"found": True, "at": name, "records": records, **caa_summary(records)}
        return {"found": False}
