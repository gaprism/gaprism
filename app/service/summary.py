"""The summary of a scan: where the data is, who processes it, how secure the external posture is,
and how much of the vendor was actually looked at.

It is computed from ``check_result`` and ``finding``, never from free text, and every list is
bounded. ``coverage_of``, ``where_of`` and ``who_of`` take plain data, so they are tested with the
real checks' recorded output; ``build_summary`` loads that data for one scan.

What the cards state are *observations*: where addresses are announced, which providers show up in
DNS, network and mail records, what the rules found. They are not storage locations, not a list of
legal processors and not a certification, and the pages say so. A check that did not produce an
answer is reported as "not determined", never as "none".
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.email import mail_provider
from app.models import CheckResult, Host, Scan
from app.service import findings as findings_service
from app.service.discovery.psl import registrable_domain

MAX_COUNTRIES = 12
MAX_CITIES = 3  # per country
MAX_NETWORKS = 8
MAX_ITEMS = 8  # per provider group
MAX_TOP_RULES = 3
LOCATION_RULE = "LOCATION_OUTSIDE_EU_CH"  # the finding that says "outside the allowed area"
DOMAIN_KEYS = ("email", "domain_dns", "registration")

FAILED_STATUSES = ("error", "unavailable")
OPEN_STATUSES = ("queued", "running")
NOT_LOCATED_STATUSES = ("no_data", "unavailable", "error")


# --------------------------------------------------------------------------- what is read


@dataclass(frozen=True)
class HostChecks:
    """What the checks said about one host, as far as the summary reads it."""

    statuses: Mapping[str, tuple[str, str | None]]  # check key -> (status, reason code)
    location: Mapping[str, Any] | None = None  # data of the ``ip`` check when it located something
    scheme: str | None = None  # ``https`` or ``http``: how the HTTP check got its answer


@dataclass(frozen=True)
class DomainResult:
    """One check of the domain itself."""

    status: str
    reason: str | None
    data: Mapping[str, Any]


def _entries(location: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    """The address entries of an ``ip`` result (anything malformed counts as none)."""
    raw = location.get("addresses") if location else None
    return [entry for entry in raw if isinstance(entry, Mapping)] if isinstance(raw, list) else []


def _country(entry: Mapping[str, Any]) -> str | None:
    country = entry.get("country")
    return str(country).upper() if country else None


def _network(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    network = entry.get("network")
    return network if isinstance(network, Mapping) else {}


def _is_edge(entry: Mapping[str, Any]) -> bool:
    return bool(_network(entry).get("edge"))


def _country_name(entries: Sequence[Mapping[str, Any]], code: str) -> str:
    """The country's name as the databases give it (the code when they gave none)."""
    for entry in entries:
        if _country(entry) == code and entry.get("country_name"):
            return str(entry["country_name"])
    return code


# --------------------------------------------------------------------------- coverage


@dataclass(frozen=True)
class Coverage:
    """How much was looked at. The five web states add up to ``hosts``."""

    names_seen: int  # certificate names the discovery sources reported
    hosts: int  # hosts reviewed
    fully_checked: int  # hosts whose every check ended with an answer
    https: int  # an HTTPS page answered
    http_only: int  # only plain HTTP answered
    no_web_server: int  # resolves, nothing answers on port 80 or 443
    no_address: int  # no public address to connect to
    undetermined: int  # the web check failed, did not run or was cancelled
    out_of_scope: int  # certificate names outside the domain, ignored
    wildcards: int  # wildcard patterns, noted but not reviewed
    over_limit: int  # hosts beyond the limit per scan
    host_limit: int | None

    @property
    def incomplete(self) -> int:
        return self.hosts - self.fully_checked

    @property
    def not_reachable(self) -> int:
        return self.no_web_server + self.no_address

    @property
    def not_reviewed(self) -> int:
        return self.out_of_scope + self.wildcards + self.over_limit


def fully_checked(host: HostChecks) -> bool:
    """Every check of the host ended with an answer: it found something, found nothing, or was left
    out because it could not apply (no address, nothing to connect to). A check that failed, was
    unavailable, did not finish or was cancelled is a gap."""
    if not host.statuses:
        return False
    for status, reason in host.statuses.values():
        if status in FAILED_STATUSES or status in OPEN_STATUSES:
            return False
        if status == "skipped" and reason == "scan_cancelled":
            return False
    return True


def _web_state(host: HostChecks) -> str:
    if host.scheme == "https":
        return "https"
    if host.scheme == "http":
        return "http_only"
    dns = host.statuses.get("dns", ("", None))
    web = host.statuses.get("http", ("", None))
    if dns[0] == "no_data" or (web[0] == "skipped" and web[1] == "no_public_address"):
        return "no_address"
    if web[0] == "no_data":
        return "no_web_server"
    return "undetermined"


def _count(value: Any) -> int:
    return int(value) if isinstance(value, int | float) else 0


def hosts_over_limit(discovery: Mapping[str, Any]) -> int:
    """How many hosts were left out because of the limit per scan: the names discovery dropped when
    it merged its sources (the apex first, then the most recently seen), plus those the scan's plan
    dropped because the domain and the hosts added by hand come first. The two never overlap."""
    counts = discovery.get("counts")
    planned = discovery.get("planned")
    merged = _count(counts.get("dropped_by_cap")) if isinstance(counts, Mapping) else 0
    planned_drop = _count(planned.get("dropped_by_cap")) if isinstance(planned, Mapping) else 0
    return merged + planned_drop


def coverage_of(
    hosts: Sequence[HostChecks], discovery: Mapping[str, Any], host_limit: int | None = None
) -> Coverage:
    """Count what was reviewed and what was not. ``discovery`` is the discovery check's data."""
    counts = discovery.get("counts")
    wildcards = discovery.get("wildcard_patterns")
    states = Counter(_web_state(host) for host in hosts)
    return Coverage(
        names_seen=_count(counts.get("names_seen")) if isinstance(counts, Mapping) else 0,
        hosts=len(hosts),
        fully_checked=sum(1 for host in hosts if fully_checked(host)),
        https=states["https"],
        http_only=states["http_only"],
        no_web_server=states["no_web_server"],
        no_address=states["no_address"],
        undetermined=states["undetermined"],
        out_of_scope=_count(counts.get("out_of_scope")) if isinstance(counts, Mapping) else 0,
        wildcards=len(wildcards) if isinstance(wildcards, list) else 0,
        over_limit=hosts_over_limit(discovery),
        host_limit=host_limit,
    )


# --------------------------------------------------------------------------- where


@dataclass(frozen=True)
class CountryLine:
    code: str
    name: str
    hosts: int
    allowed: bool
    cities: tuple[tuple[str, int], ...]  # (city, hosts), the busiest few


@dataclass(frozen=True)
class WhereCard:
    """Where the addresses of the hosts are. The location of an address is where it is announced,
    which for a CDN or anycast network is the edge, not the data centre: those hosts are counted
    apart and never as a place."""

    located: int  # hosts with an address of their own that could be placed in a country
    countries: tuple[CountryLine, ...]  # outside the allowed area first, then the busiest
    more_countries: int
    outside: int  # hosts with an address of their own outside the allowed area
    outside_edge_only: int  # hosts whose only addresses outside are CDN or anycast edges
    edge_hosts: int  # hosts that sit behind a CDN or anycast network only
    edge_networks: tuple[tuple[str, int], ...]  # (network, hosts)
    unlocated: int  # hosts with a public address that could not be placed
    unlocated_reason: str | None  # the most common reason code
    allowed_count: int  # how many countries the allowed area has
    rule_id: str = LOCATION_RULE


def where_of(hosts: Sequence[HostChecks], allowed: frozenset[str]) -> WhereCard:
    """Place the hosts. ``allowed`` is the set of country codes an address may be located in."""
    names: dict[str, str] = {}
    per_country: Counter[str] = Counter()
    per_city: dict[str, Counter[str]] = {}
    edge_networks: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    located = outside = outside_edge_only = edge_hosts = unlocated = 0

    for host in hosts:
        entries = [entry for entry in _entries(host.location) if _country(entry)]
        if not entries:
            status, reason = host.statuses.get("ip", ("", None))
            if status == "ok":  # the databases knew the network but no country
                unlocated += 1
                reasons["no_country"] += 1
            elif status in NOT_LOCATED_STATUSES:
                unlocated += 1
                reasons[reason or status] += 1
            continue  # skipped: no public address, nothing to place
        own = [entry for entry in entries if not _is_edge(entry)]
        edge = [entry for entry in entries if _is_edge(entry)]
        if own:
            located += 1
            places = {(str(_country(entry)), str(entry.get("city") or "")) for entry in own}
            for code in {code for code, _ in places}:
                per_country[code] += 1
                names.setdefault(code, _country_name(own, code))
            for code, city in places:
                if city:
                    per_city.setdefault(code, Counter())[city] += 1
        else:
            edge_hosts += 1
            for network in {str(_network(entry).get("name") or "?") for entry in edge}:
                edge_networks[network] += 1
        if any(_country(entry) not in allowed for entry in own):
            outside += 1
        elif any(_country(entry) not in allowed for entry in edge):
            outside_edge_only += 1

    lines = [
        CountryLine(
            code=code,
            name=names.get(code, code),
            hosts=count,
            allowed=code in allowed,
            cities=tuple(
                sorted(per_city.get(code, Counter()).items(), key=lambda kv: (-kv[1], kv[0]))[
                    :MAX_CITIES
                ]
            ),
        )
        for code, count in per_country.items()
    ]
    lines.sort(key=lambda line: (line.allowed, -line.hosts, line.name))  # outside first
    return WhereCard(
        located=located,
        countries=tuple(lines[:MAX_COUNTRIES]),
        more_countries=max(0, len(lines) - MAX_COUNTRIES),
        outside=outside,
        outside_edge_only=outside_edge_only,
        edge_hosts=edge_hosts,
        edge_networks=tuple(
            sorted(edge_networks.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_NETWORKS]
        ),
        unlocated=unlocated,
        unlocated_reason=reasons.most_common(1)[0][0] if reasons else None,
        allowed_count=len(allowed),
    )


# --------------------------------------------------------------------------- who


@dataclass(frozen=True)
class NetworkLine:
    name: str
    kind: str | None  # cdn | cloud | hosting, when the network hint knows
    asns: tuple[int, ...]
    hosts: int


@dataclass(frozen=True)
class Group:
    """One list of providers: what was found, that nothing was, or why it is not known."""

    state: str  # found | none | unknown
    items: tuple[tuple[str, int | None], ...] = ()  # (name, how many)
    more: int = 0
    reason: str | None = None  # for ``unknown``: the reason code


@dataclass(frozen=True)
class WhoCard:
    """Who shows up in the records: the networks hosting the hosts, the DNS operators, the mail
    providers and the sending services, the registrar."""

    networks: tuple[NetworkLine, ...]
    more_networks: int
    networks_reason: str | None  # why no network is known, when hosts have addresses
    addressed: int  # hosts with a located address (the networks are read from those)
    dns: Group
    mail: Group
    senders: Group
    registrar: Group


def _network_lines(hosts: Sequence[HostChecks]) -> list[NetworkLine]:
    """The networks the addresses of the hosts belong to, grouped by name, busiest first."""
    per_name: dict[str, dict[str, Any]] = {}
    for host in hosts:
        seen: set[str] = set()
        for entry in _entries(host.location):
            hint = _network(entry)
            asn = entry.get("asn")
            name = str(hint.get("name") or entry.get("organisation") or (f"AS{asn}" if asn else ""))
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            row = per_name.setdefault(
                name.lower(), {"name": name, "kind": hint.get("kind"), "asns": set(), "hosts": 0}
            )
            row["hosts"] += 1
            if isinstance(asn, int):
                row["asns"].add(asn)
    lines = [
        NetworkLine(
            name=row["name"],
            kind=str(row["kind"]) if row["kind"] else None,
            asns=tuple(sorted(row["asns"]))[:3],
            hosts=row["hosts"],
        )
        for row in per_name.values()
    ]
    return sorted(lines, key=lambda line: (-line.hosts, line.name.lower()))


Extract = Callable[[Mapping[str, Any]], list[tuple[str, int | None]] | None]


def _group(result: DomainResult | None, extract: Extract) -> Group:
    if result is None:
        return Group("unknown", reason="not_run")
    if result.status != "ok":
        return Group("unknown", reason=result.reason or result.status)
    items = extract(result.data)
    if items is None:  # the check ran, but this part of it could not be asked
        return Group("unknown", reason="not_determined")
    if not items:
        return Group("none")
    return Group("found", tuple(items[:MAX_ITEMS]), more=max(0, len(items) - MAX_ITEMS))


def _ranked(counts: Counter[str]) -> list[tuple[str, int | None]]:
    return [(name, n) for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def _dns_operators(data: Mapping[str, Any]) -> list[tuple[str, int | None]] | None:
    ns = data.get("ns")
    if not isinstance(ns, Mapping) or ns.get("found") is None:
        return None
    servers = ns.get("servers") if ns.get("found") else []
    return _ranked(
        Counter(
            str(row["operator"])
            for row in servers or []
            if isinstance(row, Mapping) and row.get("operator")
        )
    )


def _mail_hosts(data: Mapping[str, Any]) -> list[tuple[str, int | None]] | None:
    mx = data.get("mx")
    if not isinstance(mx, Mapping) or mx.get("found") is None:
        return None
    counts: Counter[str] = Counter()
    for record in mx.get("records") or []:
        host = (
            str(record.get("host") or "").lower().rstrip(".") if isinstance(record, Mapping) else ""
        )
        if host:
            counts[mail_provider(host) or registrable_domain(host) or host] += 1
    return _ranked(counts)


def _senders(data: Mapping[str, Any]) -> list[tuple[str, int | None]] | None:
    spf = data.get("spf")
    if not isinstance(spf, Mapping) or spf.get("found") is None:
        return None
    return [(str(name), None) for name in spf.get("senders") or []]


def _registrar(data: Mapping[str, Any]) -> list[tuple[str, int | None]] | None:
    registrar = data.get("registrar")
    if isinstance(registrar, Mapping) and registrar.get("name"):
        return [(str(registrar["name"]), None)]
    return []


def who_of(hosts: Sequence[HostChecks], domain: Mapping[str, DomainResult]) -> WhoCard:
    """The providers that show up: from the hosts' addresses and from the domain's own records."""
    networks = _network_lines(hosts)
    reasons: Counter[str] = Counter()
    for host in hosts:
        status, reason = host.statuses.get("ip", ("", None))
        if status in NOT_LOCATED_STATUSES:
            reasons[reason or status] += 1
    return WhoCard(
        networks=tuple(networks[:MAX_NETWORKS]),
        more_networks=max(0, len(networks) - MAX_NETWORKS),
        networks_reason=reasons.most_common(1)[0][0] if reasons and not networks else None,
        addressed=sum(1 for host in hosts if _entries(host.location)),
        dns=_group(domain.get("domain_dns"), _dns_operators),
        mail=_group(domain.get("email"), _mail_hosts),
        senders=_group(domain.get("email"), _senders),
        registrar=_group(domain.get("registration"), _registrar),
    )


# --------------------------------------------------------------------------- secure


@dataclass(frozen=True)
class SecureCard:
    """What the rules found that is still open, and how much of the vendor that rests on."""

    state: str  # ready | pending | failed | not_evaluated
    open_by_severity: dict[str, int] = field(default_factory=dict)
    open_total: int = 0
    accepted: int = 0
    false_positive: int = 0
    top_rules: tuple[findings_service.RuleCount, ...] = ()
    hosts: int = 0
    fully_checked: int = 0


@dataclass(frozen=True)
class ScanSummary:
    coverage: Coverage
    where: WhereCard
    who: WhoCard
    secure: SecureCard


# --------------------------------------------------------------------------- loading


def load_hosts(session: Session, scan_id: uuid.UUID) -> list[HostChecks]:
    """The checks of every host of the scan: their statuses, locations and web answer."""
    statuses: dict[uuid.UUID, dict[str, tuple[str, str | None]]] = {}
    for host_id, key, status, reason in session.execute(
        select(
            CheckResult.host_id, CheckResult.check_key, CheckResult.status, CheckResult.reason_code
        ).where(CheckResult.scan_id == scan_id, CheckResult.host_id.is_not(None))
    ):
        if host_id is not None:
            statuses.setdefault(host_id, {})[key] = (status, reason)
    located: dict[uuid.UUID, Mapping[str, Any]] = {
        host_id: data
        for host_id, data in session.execute(
            select(CheckResult.host_id, CheckResult.data).where(
                CheckResult.scan_id == scan_id,
                CheckResult.check_key == "ip",
                CheckResult.status == "ok",
                CheckResult.host_id.is_not(None),
            )
        )
        if host_id is not None
    }
    schemes: dict[uuid.UUID, str | None] = {
        host_id: scheme
        for host_id, scheme in session.execute(
            select(CheckResult.host_id, CheckResult.data["scheme"].astext).where(
                CheckResult.scan_id == scan_id,
                CheckResult.check_key == "http",
                CheckResult.status == "ok",
                CheckResult.host_id.is_not(None),
            )
        )
        if host_id is not None
    }
    host_ids = list(session.scalars(select(Host.id).where(Host.scan_id == scan_id)))
    return [
        HostChecks(statuses.get(host_id, {}), located.get(host_id), schemes.get(host_id))
        for host_id in host_ids
    ]


def load_domain(session: Session, scan_id: uuid.UUID) -> dict[str, DomainResult]:
    """The domain-level checks the summary reads (email, name servers, registration)."""
    rows = session.execute(
        select(
            CheckResult.check_key, CheckResult.status, CheckResult.reason_code, CheckResult.data
        ).where(
            CheckResult.scan_id == scan_id,
            CheckResult.host_id.is_(None),
            CheckResult.check_key.in_(DOMAIN_KEYS),
        )
    )
    return {key: DomainResult(status, reason, data or {}) for key, status, reason, data in rows}


def secure_of(
    session: Session, scan: Scan, coverage: Coverage, *, today: date | None = None
) -> SecureCard:
    state = findings_service.evaluation_state(scan)
    if state != "ready":
        return SecureCard(state, hosts=coverage.hosts, fully_checked=coverage.fully_checked)
    counted = findings_service.tally(session, scan, today=today)
    return SecureCard(
        state=state,
        open_by_severity=counted.open_by_severity,
        open_total=counted.open_total,
        accepted=counted.accepted,
        false_positive=counted.false_positive,
        top_rules=tuple(counted.open_rules[:MAX_TOP_RULES]),
        hosts=coverage.hosts,
        fully_checked=coverage.fully_checked,
    )


def build_summary(
    session: Session,
    scan: Scan,
    discovery: Mapping[str, Any],
    allowed: frozenset[str],
    *,
    today: date | None = None,
) -> ScanSummary:
    """The summary of a scan. ``discovery`` is the data of its discovery check."""
    hosts = load_hosts(session, scan.id)
    limit = scan.options.get("max_hosts") if scan.options else None
    coverage = coverage_of(hosts, discovery, int(limit) if isinstance(limit, int) else None)
    return ScanSummary(
        coverage=coverage,
        where=where_of(hosts, allowed),
        who=who_of(hosts, load_domain(session, scan.id)),
        secure=secure_of(session, scan, coverage, today=today),
    )
