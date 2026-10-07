"""Exports of a finished scan: JSON with everything, CSV of the hosts, CSV of the findings, and the
data the printable report is made of (``app/service/report.py``).

All of them read one ``ExportData``, built from the database in a fixed order (hosts by name,
checks in display order, findings open first and most serious first), so two exports of the same
scan are identical apart from the moment they were made. What an export states are stored facts
and the findings the rules drew from them; nothing is looked up again, and nothing is invented:
a check that did not answer is exported with its status and reason, not as an empty value.

JSON is meant for machines and says so (``format``, ``version``); the CSV files are meant for
spreadsheets: cells that a spreadsheet could read as a formula are neutralised, and the file starts
with a byte order mark so that Excel reads it as UTF-8. Texts (titles, messages, advice) are in the
language of the person who exports; every code and every number is language-independent.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY, observatory, reputation, takeover_services
from app.i18n import gettext as _
from app.models import Assessment, CheckResult, Host, Scan
from app.models.base import utc_now
from app.rules import RULES
from app.service import exploits as exploit_service
from app.service import findings as findings_service
from app.service import summary as summary_service
from app.service.decisions import Decision
from app.service.host_view import CHECK_ORDER, DOMAIN_CHECK_ORDER

FORMAT_NAME = "web-due-diligence-export"
FORMAT_VERSION = 1
CSV_BOM = "﻿"
MAX_EVIDENCE_SHOWN = 3  # evidence references named in a CSV cell
MAX_TECHNOLOGIES_SHOWN = 40  # technologies named in a CSV cell
CT_SOURCE_NAMES = {"ctlogs": "ctlogs.dev", "certspotter": "CertSpotter", "crtsh": "crt.sh"}

HOST_COLUMNS = (
    "hostname",
    "source",
    "addresses",
    "countries",
    "cities",
    "networks",
    "cdn_edge",
    "cdn_waf",
    "ports",
    "cves",
    "tls",
    "tls_valid_until",
    "tls_days_left",
    "http_status",
    "http_scheme",
    "technologies",
    "blocked_by",
    "open_findings",
    "top_severity",
    "gaps",
)
FINDING_COLUMNS = (
    "severity",
    "status",
    "rule_id",
    "title",
    "message",
    "host",
    "scope",
    "address",
    "subject",
    "confidence",
    "attribution",
    "advice",
    "evidence",
    "decided_by",
    "decided_at",
    "decision_reason",
    "review_by",
    "acceptance_expired",
    "fingerprint",
)


# --------------------------------------------------------------------------- what an export says


@dataclass(frozen=True)
class CheckExport:
    """One check result as stored."""

    id: uuid.UUID
    key: str
    status: str
    reason_code: str | None
    source: str | None
    collected_at: datetime | None
    duration_ms: int | None
    data: Mapping[str, Any]


@dataclass(frozen=True)
class HostExport:
    id: uuid.UUID
    hostname: str
    source: str
    ct_sources: tuple[str, ...]
    first_seen: datetime | None
    last_seen: datetime | None
    checks: tuple[CheckExport, ...]  # in display order
    open_findings: int  # its own and those about the addresses it resolves to
    top_severity: str | None

    def check(self, key: str) -> CheckExport | None:
        return next((check for check in self.checks if check.key == key), None)

    @property
    def has_gaps(self) -> bool:
        """A check failed, was unavailable, did not finish or was cancelled."""
        statuses = {check.key: (check.status, check.reason_code) for check in self.checks}
        return not summary_service.fully_checked(summary_service.HostChecks(statuses))


@dataclass(frozen=True)
class EvidenceRef:
    """The check result a finding rests on."""

    check_id: uuid.UUID
    check: str
    hostname: str | None  # None: a check of the domain itself
    collected_at: datetime | None


@dataclass(frozen=True)
class FindingExport:
    id: uuid.UUID
    rule_id: str
    rule_version: str
    severity: str
    confidence: str
    attribution: str
    scope: str  # host | address | domain
    subject: str
    fingerprint: str
    params: Mapping[str, Any]
    host_id: uuid.UUID | None
    hostname: str | None
    address: str | None
    title: str
    message: str
    advice: str
    facts: tuple[tuple[str, str], ...]
    status: str  # open | accepted | false_positive
    decision: Decision | None
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class Attribution:
    """A source of the data, what it was used for, and the terms it comes under."""

    key: str
    name: str
    used_for: str
    terms: str
    url: str | None


@dataclass(frozen=True)
class ExportData:
    generated_at: datetime
    assessment_id: uuid.UUID
    domain: str
    domain_display: str
    label: str | None
    assessment_created_at: datetime
    scan_id: uuid.UUID
    scan_status: str
    scan_created_at: datetime
    scan_started_at: datetime | None
    scan_finished_at: datetime | None
    scan_options: Mapping[str, Any]
    findings_state: str  # ready | failed | not_evaluated (pending cannot occur: scans are finished)
    findings_info: Mapping[str, Any]  # what the evaluation recorded: time, rule set, errors, cap
    summary: summary_service.ScanSummary
    discovery: Mapping[str, Any]
    domain_checks: tuple[CheckExport, ...]
    hosts: tuple[HostExport, ...]
    findings: tuple[FindingExport, ...]
    ruleset: str  # of the code that made this export
    rules: Mapping[str, int]  # rule id -> version, of the code that made this export
    attributions: tuple[Attribution, ...]

    @property
    def open_findings(self) -> tuple[FindingExport, ...]:
        return tuple(f for f in self.findings if f.status == "open")

    @property
    def decided_findings(self) -> tuple[FindingExport, ...]:
        return tuple(f for f in self.findings if f.status != "open")


def _rank(order: Sequence[str], key: str) -> tuple[int, str]:
    return (order.index(key), "") if key in order else (len(order), key)


def build_export(
    session: Session,
    assessment: Assessment,
    scan: Scan,
    config: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> ExportData:
    """Read everything an export of ``scan`` states (a handful of queries, whatever the size)."""
    moment = now or utc_now()
    today = moment.date()
    hosts = list(
        session.scalars(select(Host).where(Host.scan_id == scan.id).order_by(Host.hostname))
    )
    names = {host.id: host.hostname for host in hosts}

    by_host: dict[uuid.UUID, list[CheckExport]] = {}
    domain_checks: list[CheckExport] = []
    discovery: Mapping[str, Any] = {}
    evidence: dict[str, EvidenceRef] = {}
    sources: set[str] = set()
    for row in session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)):
        check = CheckExport(
            row.id,
            row.check_key,
            row.status,
            row.reason_code,
            row.source,
            row.collected_at,
            row.duration_ms,
            dict(row.data or {}),
        )
        hostname = names.get(row.host_id) if row.host_id is not None else None
        evidence[str(row.id)] = EvidenceRef(row.id, row.check_key, hostname, row.collected_at)
        if row.source:
            sources.add(row.source)
        if row.check_key == "ports":
            sources |= exploit_service.sources_used(check.data)
        if row.host_id is not None:
            by_host.setdefault(row.host_id, []).append(check)
        elif row.check_key == DISCOVERY_KEY:
            discovery = check.data
        else:
            domain_checks.append(check)

    open_counts = findings_service.host_summaries(session, scan, [h.id for h in hosts], today=today)
    host_exports = tuple(
        HostExport(
            id=host.id,
            hostname=host.hostname,
            source=host.source,
            ct_sources=tuple(host.ct_sources or ()),
            first_seen=host.first_seen,
            last_seen=host.last_seen,
            checks=tuple(sorted(by_host.get(host.id, []), key=lambda c: _rank(CHECK_ORDER, c.key))),
            open_findings=open_counts[host.id].count if host.id in open_counts else 0,
            top_severity=open_counts[host.id].top if host.id in open_counts else None,
        )
        for host in hosts
    )

    rows = findings_service.scan_findings(session, scan, today=today)
    views = findings_service.describe_all(session, rows, assessment.id, today=today)
    findings = tuple(
        FindingExport(
            id=row.id,
            rule_id=row.rule_id,
            rule_version=row.rule_version,
            severity=row.severity,
            confidence=row.confidence,
            attribution=row.attribution,
            scope=view.scope,
            subject=row.subject,
            fingerprint=row.fingerprint,
            params=dict(row.params or {}),
            host_id=row.host_id,
            hostname=view.hostname,
            address=view.address,
            title=view.title,
            message=view.message,
            advice=view.advice,
            facts=tuple(view.facts),
            status=view.status,
            decision=view.decision,
            evidence=tuple(evidence[e] for e in row.evidence if e in evidence),
        )
        for row, view in zip(rows, views, strict=True)
    )

    return ExportData(
        generated_at=moment,
        assessment_id=assessment.id,
        domain=assessment.domain,
        domain_display=assessment.domain_display,
        label=assessment.label,
        assessment_created_at=assessment.created_at,
        scan_id=scan.id,
        scan_status=scan.status,
        scan_created_at=scan.created_at,
        scan_started_at=scan.started_at,
        scan_finished_at=scan.finished_at,
        scan_options=dict(scan.options or {}),
        findings_state=findings_service.evaluation_state(scan),
        findings_info=dict(findings_service.evaluation_info(scan)),
        summary=summary_service.build_summary(
            session, scan, discovery, findings_service.allowed_countries(config), today=today
        ),
        discovery=discovery,
        domain_checks=tuple(sorted(domain_checks, key=lambda c: _rank(DOMAIN_CHECK_ORDER, c.key))),
        hosts=host_exports,
        findings=findings,
        ruleset=findings_service.ruleset_digest(),
        rules={rule.id: rule.version for rule in sorted(RULES.values(), key=lambda r: r.id)},
        attributions=attributions_for(sources, discovery),
    )


# --------------------------------------------------------------------------- sources


def attributions_for(
    sources: Iterable[str], discovery: Mapping[str, Any]
) -> tuple[Attribution, ...]:
    """The sources a scan actually used (by what its check results say), with their terms."""
    used = set(sources)
    found: list[Attribution] = []

    answered = [
        CT_SOURCE_NAMES.get(str(entry.get("source")), str(entry.get("source")))
        for entry in discovery.get("sources", [])
        if isinstance(entry, Mapping) and entry.get("status") == "ok"
    ]
    if answered or any(s.startswith("ct") for s in used):
        found.append(
            Attribution(
                "ct",
                _("Certificate Transparency: %(names)s", names=", ".join(answered) or "?"),
                _("The host names of the domain"),
                _("Public logs. The domain name is sent to them, each under its own terms."),
                None,
            )
        )
    resolvers = [s for s in used if s.startswith("dns:")]
    if resolvers:
        listed = resolvers[0].split(":", 1)[1] or _("the operating system's resolver")
        found.append(
            Attribution(
                "dns",
                _("DNS resolvers: %(names)s", names=listed.replace(",", ", ")),
                _("The DNS records of the hosts and of the domain"),
                _("The host names are sent to the resolvers."),
                None,
            )
        )
    if used & {"http-probe", "tls-probe", "https"}:
        found.append(
            Attribution(
                "target",
                _("The assessed hosts themselves"),
                _("TLS certificate, HTTP response headers, security.txt and the MTA-STS policy"),
                _(
                    "Standard requests: a TLS handshake and two HTTP requests per host, our own "
                    "User-Agent, no credentials, only ports 80 and 443. Five more handshakes ask "
                    "which TLS versions and kinds of suites the server accepts (nothing is sent "
                    "after a handshake). A host that is an alias for a hosted service is asked "
                    "for its home page once or twice more."
                ),
                None,
            )
        )
    if takeover_services.SOURCE in used:
        found.append(
            Attribution(
                "takeover",
                "can-i-take-over-xyz (EdOverflow and contributors)",
                _(
                    "Which hosted services show which page for a name nobody has claimed, to "
                    "recognise aliases that could be taken over"
                ),
                _(
                    "CC BY 4.0, adapted: only services that were seen to behave that way again "
                    "are kept, and the texts are the ones the services show today. The list is "
                    "part of the program; nothing about the assessment was sent for it."
                ),
                takeover_services.SOURCE_URL,
            )
        )
    security = [s for s in used if s.startswith(f"{reputation.SOURCE}:")]
    if security:
        keys = security[0].split(":", 1)[1].split(",")
        named = ", ".join(
            reputation.SECURITY_RESOLVERS[key].name
            for key in keys
            if key in reputation.SECURITY_RESOLVERS
        )
        found.append(
            Attribution(
                "reputation",
                _("Security DNS resolvers: %(names)s", names=named or "?"),
                _("Whether they block the host names as malicious"),
                _(
                    "Public resolvers, asked as any client would. The host names of the "
                    "assessment are sent to them as plain DNS questions. Blocking is their own "
                    "classification, and a name that is not blocked is not a clean bill of health."
                ),
                None,
            )
        )
    if "dbip" in used:
        found.append(
            Attribution(
                "dbip",
                "DB-IP.com (IP to City Lite, IP to ASN Lite)",
                _("Location and network of IP addresses, looked up offline"),
                _("CC BY 4.0: IP geolocation by DB-IP.com."),
                "https://db-ip.com",
            )
        )
    if "internetdb" in used:
        found.append(
            Attribution(
                "internetdb",
                "Shodan InternetDB",
                _("Open ports and CVE identifiers that a scanner saw on IP addresses"),
                _(
                    "Free for non-commercial use only. A snapshot of what a scanner saw: nothing "
                    "was scanned from here, and a port that is not listed may still be open."
                ),
                "https://internetdb.shodan.io",
            )
        )
    if "shodan" in used:
        found.append(
            Attribution(
                "shodan",
                "Shodan",
                _("Open ports and CVE identifiers that Shodan observed on IP addresses"),
                _("Used under the licence of whoever ran the scan. A snapshot, no port scan."),
                "https://www.shodan.io",
            )
        )
    if exploit_service.KEV_SOURCE in used:
        found.append(
            Attribution(
                "cisa_kev",
                exploit_service.KEV_ATTRIBUTION,
                _("Which of the reported CVEs are known to be exploited, looked up offline"),
                _(
                    "Published by CISA for anyone to use. Installed on the server that ran the "
                    "scan: nothing about the assessment was sent."
                ),
                exploit_service.KEV_URL_PAGE,
            )
        )
    if exploit_service.EPSS_SOURCE in used:
        found.append(
            Attribution(
                "first_epss",
                exploit_service.EPSS_ATTRIBUTION,
                _(
                    "The estimated probability that a reported CVE is exploited within 30 days, "
                    "looked up offline"
                ),
                _(
                    "Free to use; FIRST asks to be named as the source. Installed on the server "
                    "that ran the scan: nothing about the assessment was sent."
                ),
                exploit_service.EPSS_URL_PAGE,
            )
        )
    if any(s.startswith("rdap") for s in used):
        found.append(
            Attribution(
                "rdap",
                _("Registry RDAP services (found through IANA's bootstrap file)"),
                _("Registrar, dates, status flags and DNSSEC of the domain"),
                _(
                    "Public registry data; registrant, technical and abuse contacts are never "
                    "read. The domain name is sent to the registry."
                ),
                "https://data.iana.org/rdap/",
            )
        )
    if "hibp" in used:
        found.append(
            Attribution(
                "hibp",
                "Have I Been Pwned",
                _("Public breaches of the domain's own services"),
                _("CC BY 4.0. The domain name is sent to haveibeenpwned.com."),
                "https://haveibeenpwned.com",
            )
        )
    if "hstspreload.org" in used:
        found.append(
            Attribution(
                "hsts_preload",
                "hstspreload.org",
                _("HSTS preload status of the domain"),
                _("Public API. The domain name is sent to hstspreload.org."),
                "https://hstspreload.org",
            )
        )
    if observatory.SOURCE in used:
        found.append(
            Attribution(
                "observatory",
                _("Mozilla HTTP Observatory"),
                _("An independent grade of the security headers of the domain's home page"),
                _(
                    "Used because this installation switched it on. The domain name is sent to "
                    "Mozilla, whose scanner requests the home page and a few well-known files "
                    "from the domain's servers; the scan and its grade are public on MDN and "
                    "cannot be hidden. The grade is Mozilla's: a second opinion, not part of the "
                    "findings."
                ),
                "https://developer.mozilla.org/en-US/observatory",
            )
        )
    return tuple(found)


# --------------------------------------------------------------------------- JSON


def _iso(value: datetime | date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_default(value: object) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    raise TypeError(f"{type(value).__name__} is not part of the export format")


def _check_dict(check: CheckExport) -> dict[str, Any]:
    return {
        "id": str(check.id),
        "check": check.key,
        "status": check.status,
        "reason_code": check.reason_code,
        "source": check.source,
        "collected_at": _iso(check.collected_at),
        "duration_ms": check.duration_ms,
        "data": check.data,
    }


def _decision_dict(decision: Decision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "status": decision.status,
        "reason": decision.reason,
        "decided_by": decision.decided_by,
        "decided_at": _iso(decision.decided_at),
        "review_by": _iso(decision.review_by),
        "acceptance_expired": decision.lapsed,
    }


def _finding_dict(finding: FindingExport) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "attribution": finding.attribution,
        "scope": finding.scope,
        "subject": finding.subject,
        "fingerprint": finding.fingerprint,
        "host": finding.hostname,
        "host_id": str(finding.host_id) if finding.host_id else None,
        "address": finding.address,
        "title": finding.title,
        "message": finding.message,
        "advice": finding.advice,
        "facts": [{"label": label, "value": value} for label, value in finding.facts],
        "params": finding.params,
        "evidence": [
            {
                "check_id": str(ref.check_id),
                "check": ref.check,
                "host": ref.hostname,
                "collected_at": _iso(ref.collected_at),
            }
            for ref in finding.evidence
        ],
        "status": finding.status,
        "decision": _decision_dict(finding.decision),
    }


def _summary_dict(summary: summary_service.ScanSummary) -> dict[str, Any]:
    coverage = asdict(summary.coverage)
    coverage.update(
        incomplete=summary.coverage.incomplete,
        not_reachable=summary.coverage.not_reachable,
        not_reviewed=summary.coverage.not_reviewed,
    )
    secure = asdict(summary.secure)
    secure["open_total"] = summary.secure.open_total
    return {
        "coverage": coverage,
        "where": asdict(summary.where),
        "who": asdict(summary.who),
        "secure": secure,
    }


def to_dict(data: ExportData) -> dict[str, Any]:
    """The whole export as plain data (what ``to_json`` writes)."""
    return {
        "format": {"name": FORMAT_NAME, "version": FORMAT_VERSION},
        "generated_at": _iso(data.generated_at),
        "tool": {"name": "Web Due Diligence", "ruleset": data.ruleset, "rules": dict(data.rules)},
        "assessment": {
            "id": str(data.assessment_id),
            "domain": data.domain,
            "domain_display": data.domain_display,
            "label": data.label,
            "created_at": _iso(data.assessment_created_at),
        },
        "scan": {
            "id": str(data.scan_id),
            "status": data.scan_status,
            "created_at": _iso(data.scan_created_at),
            "started_at": _iso(data.scan_started_at),
            "finished_at": _iso(data.scan_finished_at),
            "options": dict(data.scan_options),
            "findings": {"state": data.findings_state, **data.findings_info},
        },
        "summary": _summary_dict(data.summary),
        "discovery": dict(data.discovery),
        "domain_checks": [_check_dict(check) for check in data.domain_checks],
        "hosts": [
            {
                "id": str(host.id),
                "hostname": host.hostname,
                "source": host.source,
                "ct_sources": list(host.ct_sources),
                "first_seen": _iso(host.first_seen),
                "last_seen": _iso(host.last_seen),
                "open_findings": host.open_findings,
                "top_severity": host.top_severity,
                "checks": [_check_dict(check) for check in host.checks],
            }
            for host in data.hosts
        ],
        "findings": [_finding_dict(finding) for finding in data.findings],
        "attributions": [asdict(attribution) for attribution in data.attributions],
    }


def to_json(data: ExportData) -> str:
    """The export as a JSON document (UTF-8, indented)."""
    return json.dumps(to_dict(data), ensure_ascii=False, indent=2, default=_json_default) + "\n"


# --------------------------------------------------------------------------- CSV

_FORMULA_START = ("=", "+", "-", "@")


def csv_cell(value: Any) -> str:
    """One CSV cell. Text that a spreadsheet could take for a formula gets a leading apostrophe;
    numbers are written as numbers (they cannot be formulas), lists are joined with ``; ``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, list | tuple | set | frozenset):
        text = "; ".join(csv_cell(item) for item in value)
    else:
        text = str(value)
    if text.lstrip().startswith(_FORMULA_START) or text[:1] in ("\t", "\r", "\n"):
        return "'" + text
    return text


def _write_csv(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([csv_cell(value) for value in row])
    return CSV_BOM + out.getvalue()


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


@dataclass(frozen=True)
class Places:
    """Where the addresses of a host are announced, as far as a location database knows."""

    countries: tuple[str, ...]  # ISO codes, sorted
    cities: tuple[tuple[str, str], ...]  # (city, country code), in order of appearance
    networks: tuple[str, ...]
    any_edge: bool  # some address is a CDN's or anycast edge (not counted above)
    all_edge: bool  # every address is: the host is not placed anywhere

    def named(self) -> tuple[str, ...]:
        """Each city as "Bern, CH", then the bare code of every country without a known city."""
        with_city = {country for _city, country in self.cities}
        return tuple(f"{city}, {country}" for city, country in self.cities) + tuple(
            country for country in self.countries if country not in with_city
        )


def host_places(host: HostExport) -> Places:
    """Countries, cities and networks of a host. An edge address says where a CDN announces it,
    not where the data is: it is not a place, so it is left out of countries and cities."""
    ip = host.check("ip")
    entries = [
        e
        for e in (ip.data.get("addresses", []) if ip and ip.status == "ok" else [])
        if isinstance(e, Mapping)
    ]
    own = [e for e in entries if not (e.get("network") or {}).get("edge")]
    return Places(
        countries=tuple(sorted({str(e["country"]) for e in own if e.get("country")})),
        cities=tuple(
            dict.fromkeys(
                (str(e["city"]), str(e["country"]))
                for e in own
                if e.get("city") and e.get("country")
            )
        ),
        networks=tuple(
            _unique(
                str((e.get("network") or {}).get("name") or e.get("organisation") or "")
                for e in entries
            )
        ),
        any_edge=len(own) < len(entries),
        all_edge=bool(ip and ip.status == "ok" and ip.data.get("all_edge")),
    )


def _technologies(tech: CheckExport | None) -> tuple[list[str], list[str]]:
    """The CDN, proxy or WAF recognised in front of a host, and its other technologies (with the
    version where one showed). Nothing when the check did not answer."""
    if tech is None or tech.status != "ok":
        return [], []
    edge = [str(name) for name in tech.data.get("edge", [])]
    named = [
        f"{item['name']} {item['version']}" if item.get("version") else str(item["name"])
        for item in tech.data.get("technologies", [])
        if isinstance(item, Mapping) and item.get("name") and item.get("category") != "edge"
    ]
    return edge, named[:MAX_TECHNOLOGIES_SHOWN]


def _blocked_by(check: CheckExport | None) -> list[str]:
    """The security resolvers that block the host's name (nothing when the check did not answer)."""
    if check is None or check.status != "ok":
        return []
    return [str(name) for name in check.data.get("blocked_by", [])]


def _host_row(host: HostExport) -> list[Any]:
    dns, ports = host.check("dns"), host.check("ports")
    tls, http = host.check("tls"), host.check("http")

    addresses = list(dns.data.get("addresses", [])) if dns and dns.status == "ok" else []
    places = host_places(host)

    own_ports: set[int] = set()
    cves: set[str] = set()
    if ports and ports.status == "ok":
        for entry in ports.data.get("addresses", []):
            facts = entry.get("facts") if isinstance(entry, Mapping) else None
            if facts and entry.get("attribution") != "shared_infrastructure":
                own_ports.update(p for p in facts.get("ports", []) if isinstance(p, int))
                cves.update(str(v["id"]) for v in facts.get("vulnerabilities", []) if v.get("id"))

    tls_state, valid_until, days_left = "", None, None
    if tls is not None:
        if tls.status != "ok":
            tls_state = f"{tls.status}:{tls.reason_code}" if tls.reason_code else tls.status
        elif tls.data.get("verified"):
            tls_state = "valid"
        else:
            tls_state = str((tls.data.get("failures") or ["not_verified"])[0])
        certificate = tls.data.get("certificate") or {}
        if tls.status == "ok":
            valid_until = str(certificate.get("not_after") or "")[:10] or None
            days_left = certificate.get("days_remaining")

    status = http.data.get("status") if http and http.status == "ok" else None
    scheme = http.data.get("scheme") if http and http.status == "ok" else None
    edge, technologies = _technologies(host.check("tech"))
    return [
        host.hostname,
        host.source,
        addresses,
        list(places.countries),
        [f"{city}, {country}" for city, country in places.cities],
        list(places.networks),
        places.all_edge,
        edge,
        sorted(own_ports),
        sorted(cves),
        tls_state,
        valid_until,
        days_left if isinstance(days_left, int) else None,
        status if isinstance(status, int) else None,
        scheme,
        technologies,
        _blocked_by(host.check("reputation")),
        host.open_findings,
        host.top_severity,
        host.has_gaps,
    ]


def hosts_csv(data: ExportData) -> str:
    """One row per host: where it is, who hosts it, TLS and HTTP in a few values, open findings."""
    return _write_csv(HOST_COLUMNS, (_host_row(host) for host in data.hosts))


def _evidence_text(finding: FindingExport) -> str:
    shown = [
        f"{ref.check}: {ref.hostname}" if ref.hostname else f"{ref.check}: {_('domain')}"
        for ref in finding.evidence[:MAX_EVIDENCE_SHOWN]
    ]
    more = len(finding.evidence) - MAX_EVIDENCE_SHOWN
    return "; ".join(shown) + (f"; +{more}" if more > 0 else "")


def _finding_row(finding: FindingExport) -> list[Any]:
    decision = finding.decision
    return [
        finding.severity,
        finding.status,
        finding.rule_id,
        finding.title,
        finding.message,
        finding.hostname,
        finding.scope,
        finding.address,
        finding.subject,
        finding.confidence,
        finding.attribution,
        finding.advice,
        _evidence_text(finding),
        decision.decided_by if decision else None,
        decision.decided_at if decision else None,
        decision.reason if decision else None,
        decision.review_by if decision else None,
        decision.lapsed if decision else None,
        finding.fingerprint,
    ]


def findings_csv(data: ExportData) -> str:
    """One row per finding, open ones first, with what the team decided about it."""
    return _write_csv(FINDING_COLUMNS, (_finding_row(finding) for finding in data.findings))


# --------------------------------------------------------------------------- file names


def export_filename(data: ExportData, kind: str, extension: str) -> str:
    """``example.com_2026-10-05_findings.csv``: ASCII only, whatever the domain looks like."""
    domain = re.sub(r"[^A-Za-z0-9.-]", "_", data.domain)[:100]
    return f"{domain}_{data.scan_created_at.date().isoformat()}_{kind}.{extension}"
