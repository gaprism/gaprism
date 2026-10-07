"""What the printable report says, ready to render: the export data grouped the way a reader reads
it (open findings by severity, what the team decided, the hosts in a table), and the method of the
scan in plain words. Pure: it reads an ``ExportData`` and nothing else."""

from __future__ import annotations

from dataclasses import dataclass

from app.checks.reputation import SECURITY_RESOLVERS
from app.checks.reputation import SOURCE as SECURITY_SOURCE
from app.i18n import gettext as _
from app.service.export import (
    CT_SOURCE_NAMES,
    ExportData,
    FindingExport,
    HostExport,
    host_places,
)
from app.service.findings import SEVERITIES
from app.service.host_view import CheckCell, DomainRow, check_title, summarize
from app.service.summary import hosts_over_limit

HOST_COLUMNS = ("dns", "ip", "ports", "tls", "http")
PORT_PROVIDERS = {"internetdb": "Shodan InternetDB", "shodan": "Shodan host API"}
MAX_PLACES_SHOWN = 4  # cities named in one cell of the hosts table


@dataclass(frozen=True)
class SeverityGroup:
    severity: str
    findings: tuple[FindingExport, ...]


@dataclass(frozen=True)
class ReportHost:
    """One row of the hosts table."""

    hostname: str
    source: str
    cells: dict[str, CheckCell]  # dns, ip, ports, tls, http: what each check said in a few words
    location: str  # the cities and countries its addresses are announced in, or why there are none
    open_findings: int
    top_severity: str | None
    has_gaps: bool


@dataclass(frozen=True)
class DiscoverySource:
    name: str
    status: str  # ok | unavailable | error
    reason: str | None
    names: int
    truncated: bool


@dataclass(frozen=True)
class Method:
    """How the scan went about it, as far as the stored results say."""

    discovery: tuple[DiscoverySource, ...]
    host_limit: int | None
    dropped_by_limit: int
    ports_providers: tuple[str, ...]
    location_databases: tuple[tuple[str, str], ...]  # (type, build date)
    resolvers: str | None
    security_resolvers: tuple[str, ...]  # the security DNS resolvers every host name went to
    evaluated_at: str | None
    findings_errors: tuple[str, ...]  # rules that crashed: their findings are missing


@dataclass(frozen=True)
class ReportView:
    data: ExportData
    open_groups: tuple[SeverityGroup, ...]
    decided: tuple[FindingExport, ...]
    hosts: tuple[ReportHost, ...]
    domain: tuple[DomainRow, ...]
    method: Method


def _location(host: HostExport, cell: CheckCell | None) -> str:
    """Where the host is, with cities: a CDN edge is not a place, and a host that could not be
    located says why instead of showing nothing."""
    places = host_places(host)
    named = places.named()
    if not named:
        return cell.text if cell else _("Not checked")
    text = "; ".join(named[:MAX_PLACES_SHOWN]) + ("…" if len(named) > MAX_PLACES_SHOWN else "")
    return f"{text} · {_('incl. CDN edge')}" if places.any_edge else text


def _host(host: HostExport) -> ReportHost:
    cells = {
        check.key: summarize(check.key, check.status, check.reason_code, check.data)
        for check in host.checks
        if check.key in HOST_COLUMNS
    }
    return ReportHost(
        hostname=host.hostname,
        source=host.source,
        cells=cells,
        location=_location(host, cells.get("ip")),
        open_findings=host.open_findings,
        top_severity=host.top_severity,
        has_gaps=host.has_gaps,
    )


def _method(data: ExportData) -> Method:
    sources = tuple(
        DiscoverySource(
            name=CT_SOURCE_NAMES.get(str(entry.get("source")), str(entry.get("source"))),
            status=str(entry.get("status", "")),
            reason=entry.get("reason_code"),
            names=int(entry.get("names", 0) or 0),
            truncated=bool(entry.get("truncated")),
        )
        for entry in data.discovery.get("sources", [])
        if isinstance(entry, dict)
    )
    providers: list[str] = []
    databases: list[tuple[str, str]] = []
    resolvers: str | None = None
    security: tuple[str, ...] = ()
    for host in data.hosts:
        for check in host.checks:
            if check.key == "ports" and check.source in PORT_PROVIDERS:
                name = PORT_PROVIDERS[check.source]
                if name not in providers:
                    providers.append(name)
            elif check.key == "ip" and check.status == "ok" and not databases:
                databases = [
                    (str(item.get("type")), str(item.get("build")))
                    for item in check.data.get("databases", [])
                    if isinstance(item, dict)
                ]
            elif (
                check.key == "dns" and resolvers is None and (check.source or "").startswith("dns:")
            ):
                resolvers = (check.source or "").split(":", 1)[1] or None
            elif (
                check.key == "reputation"
                and not security
                and (check.source or "").startswith(f"{SECURITY_SOURCE}:")
            ):
                keys = (check.source or "").split(":", 1)[1].split(",")
                security = tuple(
                    SECURITY_RESOLVERS[key].name for key in keys if key in SECURITY_RESOLVERS
                )
    limit = data.scan_options.get("max_hosts")
    return Method(
        discovery=sources,
        host_limit=limit if isinstance(limit, int) else None,
        dropped_by_limit=hosts_over_limit(data.discovery),
        ports_providers=tuple(providers),
        location_databases=tuple(databases),
        resolvers=resolvers,
        security_resolvers=security,
        evaluated_at=data.findings_info.get("evaluated_at"),
        findings_errors=tuple(str(rule) for rule in data.findings_info.get("errors", [])),
    )


def build_report(data: ExportData) -> ReportView:
    """Group an export for reading."""
    groups = tuple(
        SeverityGroup(severity, tuple(f for f in data.open_findings if f.severity == severity))
        for severity in SEVERITIES
        if any(f.severity == severity for f in data.open_findings)
    )
    return ReportView(
        data=data,
        open_groups=groups,
        decided=data.decided_findings,
        hosts=tuple(_host(host) for host in data.hosts),
        domain=tuple(
            DomainRow(
                check.key,
                check_title(check.key),
                summarize(check.key, check.status, check.reason_code, check.data),
            )
            for check in data.domain_checks
        ),
        method=_method(data),
    )
