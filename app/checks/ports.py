"""Ports: the open ports, services and CVEs an internet-wide scanner has seen on a host's addresses.

Needs the DNS check (only its screened public addresses are asked about) and reads the IP check's
network hint when there is one. Nothing is sent to the assessed host: the addresses go to the
provider ``PORTS_PROVIDER`` selects (the Shodan host API with the owner's key, or the keyless
Shodan InternetDB) and answers are cached per address.

What this is and is not: a snapshot of what a scanner observed, on its own schedule. A port that
is not listed is not evidence that it is closed, a listed one may be gone, and ``no_data`` only
says the database knows nothing about the address. The results belong to the *address*, so each
carries an attribution that says how far it speaks for the assessed host:

- ``shared_infrastructure``: a CDN or other shared edge; these are not this host's own servers.
- ``hostname_supported``: the provider itself lists this host name for the address.
- ``ip_only``: observed on the address the host resolves to, nothing more is known.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.checks.base import CachedAnswer, CheckContext, CheckOutcome, CheckScope, CheckStatus
from app.checks.dns import alias_names
from app.service import exploits
from app.service.geo import hint_for
from app.service.ports import PortFacts, PortsLookup, PortsProvider, build_provider
from app.service.ratelimit import KeyedLocks

log = logging.getLogger(__name__)

MAX_ADDRESSES = 4  # per host; more is a round-robin pool, which says little about one server
SHARED_HOSTNAME_COUNT = 5  # more host names than this on one address: shared hosting
SHARED_ORG_KEYWORDS = (
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "incapsula",
    "imperva",
    "sucuri",
    "azure edge",
    "google user content",
    "edgecast",
)
# After one of these the remaining addresses would fail the same way: do not ask them.
STOP_AFTER = frozenset(
    {"invalid_key", "membership_required", "rate_limited", "timeout", "connection_failed"}
)
DEFINITIVE = ("ok", "no_data")  # the only answers worth caching

ProviderFactory = Callable[[CheckContext], PortsProvider | str]
ExploitFactory = Callable[[CheckContext], exploits.ExploitLookup]


def _default_provider(ctx: CheckContext) -> PortsProvider | str:
    return build_provider(ctx.config, ctx.http)


def _default_exploits(ctx: CheckContext) -> exploits.ExploitLookup:
    directory = ctx.config.get("DATASETS_DIR")
    return exploits.shared(Path(str(directory))) if directory else exploits.NOTHING


def rank(entries: list[dict[str, Any]], lookup: exploits.ExploitLookup) -> dict[str, Any] | None:
    """Add what is known about the exploitation of each CVE to the entries (in place) and put the
    ones that matter first: known exploited, then by EPSS, then by CVSS. Returns what the lookup
    was based on, or ``None`` when no address has a CVE.

    A failing lookup never fails the check: the entries stay as the provider gave them and the
    snapshot says the data could not be read.
    """
    with_cves = [
        entry["facts"]
        for entry in entries
        if isinstance(entry.get("facts"), dict) and entry["facts"].get("vulnerabilities")
    ]
    if not with_cves:
        return None
    try:
        snapshot = lookup.snapshot()
        found = (
            lookup.lookup({v["id"] for facts in with_cves for v in facts["vulnerabilities"]})
            if snapshot.ranked_by != "none"
            else {}
        )
    except Exception:  # a broken data file must not cost the scan its ports result
        log.exception("exploitation data could not be read")
        snapshot, found = exploits.Snapshot(problem="unreadable"), {}
    summary = snapshot.to_data()
    for facts in with_cves:
        for vulnerability in facts["vulnerabilities"]:
            hit = found.get(vulnerability["id"])
            vulnerability["kev"] = hit.kev.to_data() if hit and hit.kev else None
            vulnerability["epss"] = hit.epss.to_data() if hit and hit.epss else None
        facts["vulnerabilities"].sort(key=_importance)
        facts["exploit_data"] = summary
    return summary


def _importance(vulnerability: Mapping[str, Any]) -> tuple[int, float, float]:
    """Sort key: known exploited first, then the higher EPSS score, then the higher CVSS."""
    epss = vulnerability.get("epss") or {}
    cvss = vulnerability.get("cvss")
    return (
        0 if vulnerability.get("kev") else 1,
        -float(epss.get("score", -1.0)),
        -float(cvss if isinstance(cvss, int | float) else -1.0),
    )


def attribute(
    facts: PortFacts, hostname: str | None, network: Mapping[str, Any] | None
) -> tuple[str, list[str]]:
    """How far ``facts`` speak for ``hostname``, and why (stable codes, no free text)."""
    basis: list[str] = []
    if network and network.get("edge"):
        basis.append(f"network:{network.get('name', 'edge')}")
    if any(tag.lower() == "cdn" for tag in facts.tags):
        basis.append("tag:cdn")
    owner = f"{facts.org or ''} {facts.isp or ''}".lower()
    keyword = next((word for word in SHARED_ORG_KEYWORDS if word in owner), None)
    if keyword:
        basis.append(f"org:{keyword}")
    if len(facts.hostnames) > SHARED_HOSTNAME_COUNT:
        basis.append("many_hostnames")
    if basis:
        return "shared_infrastructure", basis
    if hostname and hostname.lower() in {name.lower() for name in facts.hostnames}:
        return "hostname_supported", ["hostname_listed"]
    return "ip_only", []


def _network_hint(
    ip: str,
    ip_outcome: CheckOutcome | None,
    aliases: list[str],
    facts: PortFacts | None,
) -> Mapping[str, Any] | None:
    """The CDN/cloud hint for ``ip``: the IP check's if it ran, else one from what we know."""
    asn: int | None = None
    if ip_outcome is not None and ip_outcome.status in ("ok", "no_data"):
        for entry in ip_outcome.data.get("addresses", []):
            if entry.get("ip") != ip:
                continue
            if entry.get("network"):
                return dict(entry["network"])
            asn = entry["asn"] if isinstance(entry.get("asn"), int) else None
    hint = hint_for(asn, [*aliases, *(facts.hostnames if facts else ())])
    return hint.to_data() if hint else None


def _from_cache(answer: CachedAnswer) -> PortsLookup | None:
    """The lookup a cache entry stands for; ``None`` if it cannot be read (then it is a miss)."""
    if answer.status == "no_data":
        return PortsLookup("no_data", "no_information")
    try:
        return PortsLookup("ok", facts=PortFacts.from_data(answer.payload))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


class PortsCheck:
    """Ask the ports provider about each public address of a host."""

    key = "ports"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)
    after: tuple[str, ...] = ("ip",)

    def __init__(
        self,
        provider_factory: ProviderFactory | None = None,
        clock: Callable[[], datetime] | None = None,
        exploit_factory: ExploitFactory | None = None,
    ) -> None:
        self._provider = provider_factory or _default_provider
        self._exploits = exploit_factory or _default_exploits
        self._clock = clock or (lambda: datetime.now(UTC))
        self._flights = KeyedLocks()

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        found = [str(ip) for ip in dns.data.get("addresses", [])] if dns else []
        if dns is None or not found:
            return CheckOutcome("skipped", "no_public_address", {})
        provider = self._provider(ctx)
        if isinstance(provider, str):  # not configured: switched off, or no key for Shodan
            status: CheckStatus = "skipped" if provider == "disabled" else "unavailable"
            return CheckOutcome(status, provider, {"addresses_total": len(found)})

        addresses = found[:MAX_ADDRESSES]
        aliases = alias_names(dns.data)
        ip_outcome = ctx.previous.get("ip")
        max_age = timedelta(hours=float(ctx.config.get("PORTS_CACHE_HOURS", 24.0)))

        entries: list[dict[str, Any]] = []
        stopped = False
        for ip in addresses:
            if stopped:
                entries.append(_entry(ip, PortsLookup("unavailable", "not_asked")))
                continue
            lookup, cached, fetched_at = self._ask(provider, ip, ctx, max_age)
            entry = _entry(ip, lookup, cached, fetched_at)
            if lookup.facts is not None:
                network = _network_hint(ip, ip_outcome, aliases, lookup.facts)
                attribution, basis = attribute(lookup.facts, ctx.hostname, network)
                entry.update(attribution=attribution, attribution_basis=basis, network=network)
            entries.append(entry)
            stopped = lookup.reason in STOP_AFTER

        data: dict[str, Any] = {
            "provider": provider.name,
            "addresses": entries,
            "addresses_total": len(found),
            "truncated": len(found) > len(addresses),
        }
        ranking = rank(entries, self._exploits(ctx))
        if ranking is not None:
            data["exploit_data"] = ranking
        return _outcome(entries, data, provider.name)

    def _ask(
        self, provider: PortsProvider, ip: str, ctx: CheckContext, max_age: timedelta
    ) -> tuple[PortsLookup, bool, datetime]:
        """The provider's answer for ``ip`` (from the cache when fresh), whether it was cached,
        and when it was fetched.

        Hosts that share an address are checked at the same time; they take turns here, so the
        first asks the provider and the others find its answer in the cache.
        """
        with self._flights.hold(f"{provider.name}/{ip}"):
            if ctx.cache is not None:
                answer = ctx.cache.get(provider.name, ip, max_age)
                lookup = _from_cache(answer) if answer is not None else None
                if answer is not None and lookup is not None:
                    return lookup, True, answer.fetched_at
            lookup = provider.lookup(ip)
            fetched_at = self._clock()
            if ctx.cache is not None and lookup.status in DEFINITIVE:
                payload = lookup.facts.to_data() if lookup.facts is not None else {}
                ctx.cache.put(provider.name, ip, lookup.status, payload)
            return lookup, False, fetched_at


def _entry(
    ip: str, lookup: PortsLookup, cached: bool = False, fetched_at: datetime | None = None
) -> dict[str, Any]:
    return {
        "ip": ip,
        "status": lookup.status,
        "reason": lookup.reason,
        "cached": cached,
        "fetched_at": fetched_at.isoformat() if fetched_at else None,
        "attribution": None,
        "attribution_basis": [],
        "network": None,
        "facts": lookup.facts.to_data() if lookup.facts is not None else None,
    }


def _outcome(entries: list[dict[str, Any]], data: dict[str, Any], source: str) -> CheckOutcome:
    """One outcome from the per-address results: any answer is ``ok``; otherwise a failure
    outranks "nothing known", because an address we could not ask is not an address with no data."""
    if any(entry["status"] == "ok" for entry in entries):
        data["complete"] = all(entry["status"] in DEFINITIVE for entry in entries)
        return CheckOutcome("ok", None, data, source)
    errors = [entry for entry in entries if entry["status"] == "error"]
    if errors:
        return CheckOutcome("error", errors[0]["reason"], data, source)
    unavailable = [entry for entry in entries if entry["status"] == "unavailable"]
    if unavailable:
        return CheckOutcome("unavailable", unavailable[0]["reason"], data, source)
    return CheckOutcome("no_data", "no_information", data, source)
