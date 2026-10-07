"""Reputation: does a security DNS resolver block this host?

Resolvers such as Quad9 and Cloudflare's malware-blocking 1.1.1.2 refuse the names that their threat
intelligence flags as malware, phishing or botnet control. This check asks each enabled one for the
address of the host and compares the answer with what the DNS check found. A block shows in one or
more of three ways: an Extended DNS Error that says so (RFC 8914: Blocked, Censored, Filtered,
Prohibited), a missing name (NXDOMAIN) and an address of 0.0.0.0 or ``::``. A resolver that merely
answers differently, or fails, is never counted as a block.

The host name is sent to the resolvers, as a plain DNS question (like the DNS check's); nothing is
sent to the assessed host. ``REPUTATION_RESOLVERS`` chooses the resolvers (``none`` switches the
check off). That a name is *not* blocked says little: each resolver knows only part of the bad
names of the internet, and blocking is a third party's classification, which can be wrong.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.service.ratelimit import LIMITERS

SOURCE = "security-dns"
BLOCK_CODES = frozenset({15, 16, 17, 18})  # Blocked, Censored, Filtered, Prohibited (RFC 8914)
MAX_ANSWERS = 8
ATTEMPTS = 2  # UDP loses packets: a question that timed out is asked once more
RATE_PER_SECOND = 20.0  # per resolver, shared by all worker threads
EDNS_PAYLOAD = 1232

# Why a resolver gave no answer at all (as opposed to an answer that settles nothing).
TRANSPORT_ERRORS = frozenset({"timeout", "network_error", "bad_response", "resolver_paused"})


@dataclass(frozen=True)
class SecurityResolver:
    """A public resolver that blocks malicious names."""

    key: str
    name: str
    address: str


SECURITY_RESOLVERS: dict[str, SecurityResolver] = {
    resolver.key: resolver
    for resolver in (
        SecurityResolver("quad9", "Quad9", "9.9.9.9"),
        SecurityResolver("cloudflare", "Cloudflare (1.1.1.2)", "1.1.1.2"),
    )
}

Exchange = Callable[[dns.message.Message, str, float], dns.message.Message]


class Slots(Protocol):
    """What the check needs of a rate limiter (``app.service.ratelimit.RateLimiter`` has it)."""

    def acquire(self) -> float: ...


def udp_exchange(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
    """Ask one resolver over UDP, and over TCP when the answer does not fit."""
    response = dns.query.udp(query, address, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, address, timeout=timeout)
    return response


class ResolverHealth:
    """Stops asking a resolver that does not answer, for a while.

    A network that blocks the security resolvers would otherwise cost every host a timeout. After
    ``failures`` questions in a row without an answer a resolver is left alone for ``pause``
    seconds; the next question after that decides whether it is asked again. Shared by all threads.
    """

    def __init__(
        self,
        failures: int = 5,
        pause: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._failures = failures
        self._pause = pause
        self._clock = clock
        self._state: dict[str, tuple[int, float]] = {}  # key -> (failures in a row, paused until)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            return self._clock() >= self._state.get(key, (0, 0.0))[1]

    def record(self, key: str, answered: bool) -> None:
        with self._lock:
            if answered:
                self._state.pop(key, None)
                return
            count = self._state.get(key, (0, 0.0))[0] + 1
            paused_until = self._clock() + self._pause if count >= self._failures else 0.0
            self._state[key] = (count, paused_until)


HEALTH = ResolverHealth()


def _addresses(response: dns.message.Message) -> list[str]:
    """The addresses an answer carries (the final records of an alias chain, nothing else)."""
    found: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            found.extend(str(rdata.address) for rdata in rrset)
    return found[:MAX_ANSWERS]


def _unspecified(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_unspecified
    except ValueError:
        return False


def judge(response: dns.message.Message, baseline: list[str]) -> dict[str, Any]:
    """What one answer says: ``blocked``, ``clear`` or ``unknown`` (never a guess).

    ``baseline`` is what the DNS check found for the host: only against a name that does resolve
    can a refusal or an empty address mean a block."""
    rcode = response.rcode()
    ede = sorted(
        {int(option.code) for option in response.options if isinstance(option, dns.edns.EDEOption)}
    )
    answers = _addresses(response)
    usable = any(not _unspecified(address) for address in answers)
    sinkhole = bool(answers) and not usable
    resolves = any(not _unspecified(address) for address in baseline)
    fact: dict[str, Any] = {
        "rcode": dns.rcode.to_text(rcode),
        "ede": ede,
        "answers": answers,
        "verdict": "unknown",
        "how": None,
        "error": None,
    }
    if set(ede) & BLOCK_CODES or (sinkhole and resolves):
        fact["verdict"] = "blocked"
        if rcode == dns.rcode.NXDOMAIN:
            fact["how"] = "nxdomain"
        else:
            fact["how"] = "unspecified_address" if sinkhole else "ede"
    elif rcode == dns.rcode.NOERROR and (usable or sinkhole):
        fact["verdict"] = (
            "clear"  # (a host that resolves to nothing usable anywhere: no difference)
        )
    elif rcode == dns.rcode.NXDOMAIN:
        fact["error"] = (
            "nxdomain_unexplained"  # it resolves elsewhere, and nobody says why not here
        )
    elif rcode == dns.rcode.SERVFAIL:
        fact["error"] = "servfail"
    elif rcode == dns.rcode.REFUSED:
        fact["error"] = "resolver_refused"
    elif rcode == dns.rcode.NOERROR:
        fact["error"] = "no_answer"
    else:
        fact["error"] = "unexpected_rcode"
    return fact


def baseline_of(dns_data: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    """The record type to ask about and the addresses the DNS check found for it (any, private
    ones too: only the name travels)."""
    for key, rdtype in (("a", "A"), ("aaaa", "AAAA")):
        records = dns_data.get(key)
        found = [
            str(record["ip"])
            for record in (records if isinstance(records, list) else [])
            if isinstance(record, Mapping) and record.get("ip")
        ]
        if found:
            return rdtype, found[:MAX_ANSWERS]
    return None, []


class ReputationCheck:
    """Ask the security resolvers whether they block the host."""

    key = "reputation"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(
        self,
        exchange: Exchange = udp_exchange,
        health: ResolverHealth | None = None,
        limiter: Callable[[str], Slots] | None = None,
    ) -> None:
        self._exchange = exchange
        self._health = health or HEALTH
        self._limiter = limiter or (lambda key: LIMITERS.get(f"{SOURCE}:{key}", RATE_PER_SECOND))

    def run(self, ctx: CheckContext) -> CheckOutcome:
        host = (ctx.hostname or "").lower().rstrip(".")
        enabled = [
            SECURITY_RESOLVERS[key]
            for key in ctx.config.get("REPUTATION_RESOLVERS", [])
            if key in SECURITY_RESOLVERS
        ]
        if not enabled:  # the owner's decision, not a failure: no gap and no "partial" scan
            return CheckOutcome("skipped", "disabled", {"host": host})
        found = ctx.previous.get("dns")
        rdtype, baseline = baseline_of(found.data if found is not None else {})
        if rdtype is None:
            return CheckOutcome("skipped", "no_address_record", {"host": host})
        try:
            query = dns.message.make_query(host, rdtype, use_edns=0, payload=EDNS_PAYLOAD)
        except dns.exception.DNSException:
            return CheckOutcome("error", "invalid_name", {"host": host})

        lifetime = float(ctx.config.get("DNS_TIMEOUT_SECONDS", 5.0))
        timeout = max(0.5, min(2.0, lifetime / 2))
        rows = [self._ask(resolver, query, baseline, timeout) for resolver in enabled]
        responded = [row for row in rows if row["error"] not in TRANSPORT_ERRORS]
        decided = [row for row in rows if row["verdict"] != "unknown"]
        data: dict[str, Any] = {
            "host": host,
            "asked": rdtype,
            "baseline": baseline,
            "resolvers": rows,
            "blocked_by": [row["name"] for row in rows if row["verdict"] == "blocked"],
            "decided": len(decided),
        }
        source = f"{SOURCE}:{','.join(resolver.key for resolver in enabled)}"
        if not responded:  # why each one failed is in the rows
            return CheckOutcome("error", "no_resolver_answered", data, source)
        if not decided:
            return CheckOutcome("no_data", "no_verdict", data, source)
        return CheckOutcome("ok", data=data, source=source)

    def _ask(
        self,
        resolver: SecurityResolver,
        query: dns.message.Message,
        baseline: list[str],
        timeout: float,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "key": resolver.key,
            "name": resolver.name,
            "address": resolver.address,
            "verdict": "unknown",
            "how": None,
            "rcode": None,
            "ede": [],
            "answers": [],
            "error": None,
        }
        if not self._health.allow(resolver.key):
            return {**row, "error": "resolver_paused"}
        self._limiter(resolver.key).acquire()
        error = "timeout"
        for _attempt in range(ATTEMPTS):
            try:
                response = self._exchange(query, resolver.address, timeout)
            except dns.exception.Timeout:
                continue
            except dns.exception.DNSException:  # an answer from the wrong source, or malformed
                error = "bad_response"
                break
            except OSError:
                error = "network_error"
                break
            self._health.record(resolver.key, True)
            return {**row, **judge(response, baseline)}
        self._health.record(resolver.key, False)
        return {**row, "error": error}
