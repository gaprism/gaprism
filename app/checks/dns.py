"""DNS: where a host name points, and its mail, name-server, TXT and CAA records.

The queries go to a resolver (``EGRESS_DNS_RESOLVERS``, or the system resolver), never to the
assessed host. Every address is screened with the egress gate's rules: private, loopback and
other non-public answers are recorded as ``blocked`` (a finding in itself) and are never handed
to a check that connects. Problems stay typed: a timeout is an ``error`` entry, not an empty
record list.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import dns.exception
import dns.resolver
import dns.reversename
from dns.rdtypes.ANY.CAA import CAA
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.NS import NS
from dns.rdtypes.ANY.PTR import PTR
from dns.rdtypes.ANY.TXT import TXT
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from runner.dns import ip_block_reason

MAX_RECORDS = 50  # per record type; more are counted in ``truncated``
MAX_TEXT = 2000  # characters of one TXT value
MAX_CNAME_DEPTH = 8
OTHER_TYPES = ("MX", "NS", "TXT", "CAA")


class ResolverLike(Protocol):
    """The part of ``dns.resolver.Resolver`` the check uses (tests substitute a fake)."""

    def resolve(
        self, qname: str, rdtype: str, *, lifetime: float | None = None
    ) -> dns.resolver.Answer: ...


@dataclass
class _Lookup:
    """The answer to one question: records, or a typed reason why there are none."""

    records: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None  # timeout | servfail | network_error | dns_error
    nxdomain: bool = False


@dataclass
class _Chain:
    steps: list[dict[str, Any]] = field(default_factory=list)
    canonical: str = ""
    problem: str | None = None  # cname_loop | cname_chain_too_long | a lookup error
    dangling: bool = False  # the last target does not exist


def _name(value: Any) -> str:
    return str(value.to_text(omit_final_dot=True)).lower()


def _describe(rdata: Any) -> dict[str, Any] | None:
    """One record as plain data, or ``None`` for a type we do not interpret."""
    if isinstance(rdata, A | AAAA):
        return {"ip": rdata.address}
    if isinstance(rdata, CNAME):
        return {"target": _name(rdata.target)}
    if isinstance(rdata, MX):
        return {"preference": int(rdata.preference), "host": _name(rdata.exchange)}
    if isinstance(rdata, NS | PTR):
        return {"host": _name(rdata.target)}
    if isinstance(rdata, TXT):
        return {"value": b"".join(rdata.strings).decode("utf-8", "replace")[:MAX_TEXT]}
    if isinstance(rdata, CAA):
        return {
            "flags": int(rdata.flags),
            "tag": rdata.tag.decode("ascii", "replace"),
            "value": rdata.value.decode("utf-8", "replace")[:MAX_TEXT],
        }
    return None


def _lookup(resolver: ResolverLike, name: str, rdtype: str, lifetime: float) -> _Lookup:
    try:
        answer = resolver.resolve(name, rdtype, lifetime=lifetime)
    except dns.resolver.NXDOMAIN:
        return _Lookup(nxdomain=True)
    except dns.resolver.NoAnswer:
        return _Lookup()  # the name exists, it just has no record of this type
    except dns.resolver.NoNameservers:
        return _Lookup(error="servfail")
    except dns.exception.Timeout:
        return _Lookup(error="timeout")
    except dns.exception.DNSException:
        return _Lookup(error="dns_error")
    except OSError:
        return _Lookup(error="network_error")
    rrset = answer.rrset
    if rrset is None:
        return _Lookup()
    records: list[dict[str, Any]] = []
    for rdata in rrset:
        described = _describe(rdata)
        if described is not None:
            records.append({**described, "ttl": int(rrset.ttl)})
    return _Lookup(records=records[:MAX_RECORDS], truncated=len(records) > MAX_RECORDS)


def _follow_cnames(resolver: ResolverLike, host: str, first: _Lookup, lifetime: float) -> _Chain:
    """Walk the explicit CNAME records starting at ``host`` (``first`` is its CNAME lookup)."""
    chain = _Chain(canonical=host)
    seen = {host}
    step = first
    for _ in range(MAX_CNAME_DEPTH):
        if step.error:
            chain.problem = step.error
            return chain
        if not step.records:
            # Nothing further. A chain that ended in "no such name" points at nothing (dangling).
            chain.dangling = bool(chain.steps) and step.nxdomain
            return chain
        record = step.records[0]
        target = str(record["target"])
        chain.steps.append({"name": chain.canonical, "target": target, "ttl": record["ttl"]})
        chain.canonical = target
        if target in seen:
            chain.problem = "cname_loop"
            return chain
        seen.add(target)
        step = _lookup(resolver, target, "CNAME", lifetime)
    chain.problem = "cname_chain_too_long"
    return chain


def _build_resolver(config: Mapping[str, Any]) -> ResolverLike:
    nameservers = [str(server) for server in config.get("EGRESS_DNS_RESOLVERS", [])]
    timeout = float(config.get("DNS_TIMEOUT_SECONDS", 5.0))
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout / 2  # one attempt; the lifetime bounds all attempts of a query
    resolver.lifetime = timeout
    return resolver


def reverse_names(resolver: ResolverLike, ip: str, lifetime: float) -> tuple[list[str], str | None]:
    """The PTR names of ``ip`` and, if the lookup failed, a code saying why (never a guess)."""
    name = dns.reversename.from_address(ip).to_text()
    result = _lookup(resolver, name, "PTR", lifetime)
    return [str(record["host"]) for record in result.records], result.error


class ResolverCache:
    """One resolver per (servers, timeout) configuration, shared by all threads."""

    def __init__(self, factory: Callable[[Mapping[str, Any]], ResolverLike]) -> None:
        self._factory = factory
        self._resolvers: dict[tuple[tuple[str, ...], float], ResolverLike] = {}
        self._lock = threading.Lock()

    def get(self, config: Mapping[str, Any]) -> ResolverLike:
        servers = tuple(str(server) for server in config.get("EGRESS_DNS_RESOLVERS", []))
        timeout = float(config.get("DNS_TIMEOUT_SECONDS", 5.0))
        with self._lock:
            if (servers, timeout) not in self._resolvers:
                self._resolvers[(servers, timeout)] = self._factory(config)
            return self._resolvers[(servers, timeout)]


SHARED_RESOLVERS = ResolverCache(_build_resolver)


def lookup_addresses(resolver: ResolverLike, name: str, lifetime: float) -> list[str]:
    """Every A and AAAA address of ``name`` (not screened: the caller's gate does that).

    Empty when the name has none or the lookups failed; callers treat that as "cannot connect".
    """
    found: list[str] = []
    for rdtype in ("A", "AAAA"):
        for record in _lookup(resolver, name, rdtype, lifetime).records:
            ip = str(record["ip"])
            if ip not in found:
                found.append(ip)
    return found


class DnsCheck:
    """Resolve a host: address records, the CNAME chain, MX, NS, TXT and CAA."""

    key = "dns"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ()

    def __init__(
        self, resolver_factory: Callable[[Mapping[str, Any]], ResolverLike] | None = None
    ) -> None:
        self._resolvers = ResolverCache(resolver_factory or _build_resolver)

    def run(self, ctx: CheckContext) -> CheckOutcome:
        host = (ctx.hostname or "").lower().rstrip(".")
        if not host:
            return CheckOutcome("error", "no_hostname")
        resolver = self._resolvers.get(ctx.config)
        lifetime = float(ctx.config.get("DNS_TIMEOUT_SECONDS", 5.0))
        servers = [str(server) for server in ctx.config.get("EGRESS_DNS_RESOLVERS", [])]
        source = ("dns:" + (",".join(servers) if servers else "system"))[:64]

        first = _lookup(resolver, host, "CNAME", lifetime)
        if first.nxdomain:
            return CheckOutcome(
                "no_data", "nxdomain", {"nxdomain": True, "resolvers": servers}, source
            )
        chain = _follow_cnames(resolver, host, first, lifetime)

        lookups: dict[str, _Lookup] = {"A": _lookup(resolver, host, "A", lifetime)}
        if first.error and lookups["A"].error:
            # Two failures in a row: the resolver is unreachable. Do not spend a timeout on every
            # remaining record type of every host.
            return CheckOutcome("error", first.error, {"resolvers": servers}, source)
        dangling = chain.dangling or (bool(chain.steps) and lookups["A"].nxdomain)
        for rdtype in ("AAAA", *OTHER_TYPES):
            lookups[rdtype] = _lookup(resolver, host, rdtype, lifetime)

        addresses: list[str] = []
        blocked: list[dict[str, str]] = []
        for rdtype in ("A", "AAAA"):
            for record in lookups[rdtype].records:
                ip = str(record["ip"])
                reason = ip_block_reason(ip)
                if reason is None:
                    if ip not in addresses:
                        addresses.append(ip)
                else:
                    blocked.append({"ip": ip, "reason": reason})

        errors = {rdtype: look.error for rdtype, look in lookups.items() if look.error}
        if first.error:
            errors["CNAME"] = first.error
        elif chain.problem:
            errors["CNAME"] = chain.problem
        truncated = [rdtype for rdtype, look in lookups.items() if look.truncated]
        data: dict[str, Any] = {
            "resolvers": servers,
            "a": lookups["A"].records,
            "aaaa": lookups["AAAA"].records,
            "cname": chain.steps,
            "canonical_name": chain.canonical,
            "dangling_cname": dangling,
            "mx": lookups["MX"].records,
            "ns": lookups["NS"].records,
            "txt": lookups["TXT"].records,
            "caa": lookups["CAA"].records,
            "addresses": addresses,
            "blocked": blocked,
            "errors": errors,
            "truncated": truncated,
        }
        found = bool(chain.steps) or any(look.records for look in lookups.values())
        if found:
            return CheckOutcome("ok", data=data, source=source)
        if errors:
            return CheckOutcome("error", next(iter(errors.values())), data, source)
        return CheckOutcome("no_data", "no_records", data, source)
