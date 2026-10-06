"""Findings of a scan: running the rules over its results, storing them, and reading them back.

``evaluate_scan`` is called when a scan finishes (and by ``flask findings evaluate``): it loads
every stored check result of the scan, runs the rules (``app/rules``) and replaces the scan's
findings. Evidence stays in ``check_result``; a finding only points at it. The summary of the
evaluation (counts, which rule set ran, rules that crashed) goes into ``scan.summary['findings']``.

``describe`` turns a stored finding into text for the pages: the rule's title and one-sentence
message in the current language, the facts worth showing, and where its evidence lives.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy import and_, case, delete, func, or_, select
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY
from app.config import DEFAULT_DATA_LOCATION_ALLOWED
from app.i18n import gettext as _
from app.models import Assessment, CheckResult, Finding, Host, Scan
from app.models.base import utc_now
from app.rules import (
    RULES,
    SEVERITY_RANK,
    HostFacts,
    Result,
    Rule,
    RuleFinding,
    RuleSettings,
    ScanFacts,
    evaluate,
)
from app.rules.base import N_
from app.rules.engine import MAX_FINDINGS
from app.service.decisions import (
    ACCEPTED,
    FALSE_POSITIVE,
    OPEN,
    Decision,
    current_status,
    load_decisions,
    with_decisions,
)
from app.service.exploits import epss_percent
from app.service.host_view import problem_label, tls_failure_label

log = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low", "informational")  # most serious first
PENDING_STATUSES = ("queued", "running")
MAX_SHOWN_FACTS = 12
PLACEHOLDER = re.compile(r"%\((\w+)\)s")


# --------------------------------------------------------------------------- the rule set


def ruleset_digest() -> str:
    """A short digest of the rule ids and versions: which rules produced a scan's findings."""
    text = ",".join(
        f"{rule.id}:{rule.version}" for rule in sorted(RULES.values(), key=lambda r: r.id)
    )
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def allowed_countries(config: Mapping[str, Any]) -> frozenset[str]:
    """Where an address may be located. A missing setting means the default area, never an empty
    one (which would flag every location)."""
    allowed = config.get("DATA_LOCATION_ALLOWED") or DEFAULT_DATA_LOCATION_ALLOWED
    return frozenset(str(code).upper() for code in allowed)


def settings_for(domain: str, config: Mapping[str, Any], now: datetime) -> RuleSettings:
    """The configurable parts of the rules."""
    return RuleSettings(
        domain=domain,
        now=now,
        allowed_countries=allowed_countries(config),
        breach_recent_months=int(config.get("BREACH_RECENT_MONTHS", 24)),
    )


# --------------------------------------------------------------------------- evaluating


def load_facts(session: Session, scan: Scan) -> ScanFacts:
    """Every finished check result of the scan, grouped by host and for the domain."""
    assessment = session.get(Assessment, scan.assessment_id)
    domain = assessment.domain if assessment else ""
    hosts = list(session.scalars(select(Host).where(Host.scan_id == scan.id)))
    rows = session.execute(
        select(
            CheckResult.id,
            CheckResult.host_id,
            CheckResult.check_key,
            CheckResult.status,
            CheckResult.reason_code,
            CheckResult.data,
        ).where(CheckResult.scan_id == scan.id, CheckResult.status.not_in(PENDING_STATUSES))
    )
    per_host: dict[uuid.UUID, dict[str, Result]] = {}
    domain_results: dict[str, Result] = {}
    for result_id, host_id, key, status, reason, data in rows:
        result = Result(str(result_id), status, reason, dict(data or {}))
        if host_id is not None:
            per_host.setdefault(host_id, {})[key] = result
        elif key != DISCOVERY_KEY:
            domain_results[key] = result
    return ScanFacts(
        domain=domain,
        hosts=[HostFacts(str(h.id), h.hostname, h.source, per_host.get(h.id, {})) for h in hosts],
        domain_results=domain_results,
    )


@dataclass(frozen=True)
class EvaluationSummary:
    total: int
    by_severity: dict[str, int]
    errors: list[str]
    dropped: int


def _row(scan: Scan, finding: RuleFinding) -> Finding:
    return Finding(
        scan_id=scan.id,
        host_id=uuid.UUID(finding.host_id) if finding.host_id else None,
        rule_id=finding.rule_id,
        rule_version=str(finding.rule_version),
        subject=finding.subject,
        severity=finding.severity,
        confidence=finding.confidence,
        attribution=finding.attribution,
        params=finding.params,
        evidence=list(finding.evidence),
        fingerprint=finding.fingerprint,
    )


def evaluate_scan(
    session: Session, scan: Scan, config: Mapping[str, Any], *, now: datetime | None = None
) -> EvaluationSummary:
    """Run the rules over a scan and replace its findings. The caller commits.

    Decisions people made about findings (S2.6) are keyed by fingerprint, so they are not touched.
    """
    moment = now or utc_now()
    facts = load_facts(session, scan)
    evaluation = evaluate(facts, settings_for(facts.domain, config, moment))
    session.execute(delete(Finding).where(Finding.scan_id == scan.id))
    session.add_all([_row(scan, finding) for finding in evaluation.findings])
    session.flush()
    counts: Counter[str] = Counter(f.severity for f in evaluation.findings)
    summary = EvaluationSummary(
        total=len(evaluation.findings),
        by_severity={s: counts[s] for s in SEVERITIES if counts[s]},
        errors=evaluation.errors,
        dropped=evaluation.dropped,
    )
    scan.summary = {
        **(scan.summary or {}),
        "findings": {
            "evaluated_at": moment.isoformat(),
            "ruleset": ruleset_digest(),
            "total": summary.total,
            "by_severity": summary.by_severity,
            "errors": summary.errors,
            "dropped": summary.dropped,
        },
    }
    return summary


# --------------------------------------------------------------------------- reading


@dataclass(frozen=True)
class FindingPage:
    rows: list[Finding]
    total: int
    page: int
    per_page: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.per_page))


def _severity_order() -> Any:
    return case(
        *[(Finding.severity == name, rank) for name, rank in SEVERITY_RANK.items()], else_=-1
    )


def _in_order(query: Any, status: Any = None) -> Any:
    """Most serious first (open ones before decided ones when ``status`` is given); ties in a
    stable order so that paging never repeats or skips a row."""
    keys = [_severity_order().desc(), Finding.rule_id, Finding.subject, Finding.fingerprint]
    if status is not None:
        keys.insert(0, status != OPEN)  # false sorts before true
    return query.order_by(*keys)


def _addresses_by_host(
    session: Session, scan_id: uuid.UUID, host_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, set[str]]:
    """The public addresses each host resolved to (from its DNS result)."""
    rows = session.execute(
        select(CheckResult.host_id, CheckResult.data["addresses"]).where(
            CheckResult.scan_id == scan_id,
            CheckResult.check_key == "dns",
            CheckResult.host_id.in_(host_ids),
        )
    )
    return {
        host_id: {str(address) for address in addresses if isinstance(address, str)}
        for host_id, addresses in rows
        if isinstance(addresses, list)
    }


def _on_addresses(scan_id: uuid.UUID, addresses: Sequence[str]) -> Any:
    """SQL condition: address-level findings of the scan about one of these addresses."""
    return and_(
        Finding.scan_id == scan_id,
        Finding.host_id.is_(None),
        Finding.attribution != "domain",
        Finding.params["ip"].astext.in_(list(addresses)),
    )


def _about_host(session: Session, scan: Scan, host_id: uuid.UUID) -> Any:
    """SQL condition: the findings about a host: its own, and those about the addresses it
    resolves to."""
    addresses = sorted(_addresses_by_host(session, scan.id, [host_id]).get(host_id, set()))
    own = Finding.host_id == host_id
    return or_(own, _on_addresses(scan.id, addresses)) if addresses else own


def list_findings(
    session: Session,
    scan: Scan,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    host_id: uuid.UUID | None = None,
    status: str = "all",
    page: int = 1,
    per_page: int = 50,
    today: date | None = None,
) -> FindingPage:
    """Findings of a scan, filtered and paged in SQL, most serious first.

    ``status`` is ``open``, ``accepted``, ``false_positive`` or ``all`` (open ones first)."""
    page = max(1, page)
    per_page = max(1, min(per_page, 200))
    current = current_status(today or utc_now().date())
    query = with_decisions(select(Finding), scan.assessment_id).where(Finding.scan_id == scan.id)
    if status in (OPEN, ACCEPTED, FALSE_POSITIVE):
        query = query.where(current == status)
    if severity in SEVERITY_RANK:
        query = query.where(Finding.severity == severity)
    if rule_id:
        query = query.where(Finding.rule_id == rule_id)
    if host_id is not None:
        query = query.where(_about_host(session, scan, host_id))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    ordered = _in_order(query, current).limit(per_page).offset((page - 1) * per_page)
    return FindingPage(list(session.scalars(ordered)), total, page, per_page)


def scan_findings(session: Session, scan: Scan, *, today: date | None = None) -> list[Finding]:
    """Every finding of the scan, open ones first and then most serious first.

    Bounded by the rule engine's cap per scan; the exports read the whole list."""
    current = current_status(today or utc_now().date())
    query = with_decisions(select(Finding), scan.assessment_id).where(Finding.scan_id == scan.id)
    return list(session.scalars(_in_order(query, current).limit(MAX_FINDINGS)))


@dataclass(frozen=True)
class RuleCount:
    """One rule that fired: how often, and the most serious of its findings."""

    rule_id: str
    title: str
    severity: str
    count: int


def _rule_counts(levels: Mapping[str, Mapping[str, int]]) -> list[RuleCount]:
    """``{rule: {severity: count}}`` as lines: most serious first, then the most findings."""
    counted = [
        RuleCount(
            rule_id=rule_id,
            title=_rule_title(rule_id),
            severity=min(by_severity, key=SEVERITIES.index),
            count=sum(by_severity.values()),
        )
        for rule_id, by_severity in levels.items()
    ]
    return sorted(counted, key=lambda r: (SEVERITIES.index(r.severity), -r.count, r.title))


@dataclass(frozen=True)
class Breakdown:
    """The findings of a scan counted by status, rule and severity."""

    cells: Mapping[str, Mapping[str, Mapping[str, int]]]  # status -> rule -> severity -> count

    def _merged(self, status: str) -> dict[str, dict[str, int]]:
        wanted = (OPEN, ACCEPTED, FALSE_POSITIVE) if status == "all" else (status,)
        merged: dict[str, dict[str, int]] = {}
        for each in wanted:
            for rule_id, levels in self.cells.get(each, {}).items():
                into = merged.setdefault(rule_id, {})
                for severity, count in levels.items():
                    into[severity] = into.get(severity, 0) + count
        return merged

    def total(self, status: str = "all") -> int:
        return sum(sum(levels.values()) for levels in self._merged(status).values())

    def by_severity(self, status: str = "all") -> dict[str, int]:
        """Only the severities that occur, most serious first."""
        counted: Counter[str] = Counter()
        for levels in self._merged(status).values():
            counted.update(levels)
        return {s: counted[s] for s in SEVERITIES if counted[s]}

    def rules(self, status: str = "all") -> list[RuleCount]:
        return _rule_counts(self._merged(status))


def breakdown(session: Session, scan: Scan, *, today: date | None = None) -> Breakdown:
    """Count the findings of a scan by status, rule and severity (one query)."""
    current = (
        with_decisions(
            select(
                Finding.rule_id.label("rule_id"),
                Finding.severity.label("severity"),
                current_status(today or utc_now().date()).label("status"),
            ).select_from(Finding),
            scan.assessment_id,
        )
        .where(Finding.scan_id == scan.id)
        .subquery()
    )
    rows = session.execute(
        select(current.c.rule_id, current.c.severity, current.c.status, func.count()).group_by(
            current.c.rule_id, current.c.severity, current.c.status
        )
    ).all()
    cells: dict[str, dict[str, dict[str, int]]] = {}
    for rule_id, severity, status, count in rows:
        cells.setdefault(status, {}).setdefault(rule_id, {})[severity] = int(count)
    return Breakdown(cells)


@dataclass(frozen=True)
class Tally:
    """The findings of a scan by what they currently are: the open ones in detail, the ones
    somebody decided about as counts."""

    open_by_severity: dict[str, int]  # only the severities that occur, most serious first
    open_rules: list[RuleCount]  # most serious first
    accepted: int
    false_positive: int

    @property
    def open_total(self) -> int:
        return sum(self.open_by_severity.values())


def tally(session: Session, scan: Scan, *, today: date | None = None) -> Tally:
    """Count the findings of a scan by status (one query)."""
    counted = breakdown(session, scan, today=today)
    return Tally(
        open_by_severity=counted.by_severity(OPEN),
        open_rules=counted.rules(OPEN),
        accepted=counted.total(ACCEPTED),
        false_positive=counted.total(FALSE_POSITIVE),
    )


def _rule_title(rule_id: str) -> str:
    rule = RULES.get(rule_id)
    return _(rule.title) if rule else rule_id


# --------------------------------------------------------------------------- words for the pages

SEVERITY_LABELS = {
    "critical": N_("Critical"),
    "high": N_("High"),
    "medium": N_("Medium"),
    "low": N_("Low"),
    "informational": N_("Informational"),
}
CONFIDENCE_LABELS = {
    "high": N_("High confidence"),
    "medium": N_("Medium confidence"),
    "low": N_("Low confidence"),
    "unknown": N_("Confidence unknown"),
}
ATTRIBUTION_LABELS = {
    "hostname_supported": N_("Confirmed for this hostname"),
    "ip_only": N_("Seen on the address only"),
    "shared_infrastructure": N_("Shared infrastructure"),
    "domain": N_("Whole domain"),
}


STATUS_LABELS = {
    OPEN: N_("Open"),
    ACCEPTED: N_("Accepted"),
    FALSE_POSITIVE: N_("False positive"),
    "all": N_("All"),
}


def severity_label(severity: str) -> str:
    return _(SEVERITY_LABELS.get(severity, severity))


def status_label(status: str) -> str:
    return _(STATUS_LABELS.get(status, status))


def severity_tone(severity: str) -> str:
    """The badge colour of a severity (the badge component calls the lowest one ``info``)."""
    return "info" if severity == "informational" else severity


def confidence_label(confidence: str) -> str:
    return _(CONFIDENCE_LABELS.get(confidence, confidence))


def attribution_label(attribution: str) -> str:
    return _(ATTRIBUTION_LABELS.get(attribution, attribution))


def _failure_label(code: str) -> str:
    return tls_failure_label(code)


def _ending_label(value: str) -> str:
    return _("no all term") if value == "no all term" else value


def _ranked_by_label(code: str) -> str:
    labels = {
        "kev_epss": _("CISA KEV and EPSS"),
        "kev": _("CISA KEV only (EPSS is not installed)"),
        "epss": _("EPSS only (the KEV catalogue is not installed)"),
    }
    return labels.get(code) or _("not ranked: the exploitation data is not installed")


def _epss_label(code: str) -> str:
    try:
        return epss_percent(float(code))
    except ValueError:
        return code


# Parameter values that are codes get translated before they go into a sentence.
TRANSLATORS = {
    "failures": _failure_label,
    "problems": problem_label,
    "ending": _ending_label,
    "ranked_by": _ranked_by_label,
    "max_epss": _epss_label,
}


def _text(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return _("Yes") if value else _("No")
    return str(value)


def render_value(key: str, value: Any) -> str:
    """One parameter as text: codes translated, lists joined, nothing left as ``None``."""
    translate = TRANSLATORS.get(key)
    if isinstance(value, list | tuple):
        items = [translate(str(v)) if translate else _text(v) for v in value]
        return ", ".join(items) if items else "—"
    return translate(str(value)) if translate and value is not None else _text(value)


# --------------------------------------------------------------------------- describing


@dataclass(frozen=True)
class EvidenceLink:
    """Where the evidence of a finding is shown: a check section of a host or of the domain."""

    host_id: uuid.UUID | None  # None: the checks of the domain itself
    check: str


@dataclass(frozen=True)
class FindingView:
    """A finding in words, for the pages."""

    id: uuid.UUID
    rule_id: str
    title: str
    message: str
    advice: str
    severity: str
    confidence: str
    attribution: str
    subject: str
    scope: str  # host | address | domain: what the finding is about
    host_id: uuid.UUID | None
    hostname: str | None
    address: str | None  # for address-level findings
    facts: list[tuple[str, str]]
    evidence: EvidenceLink | None
    status: str  # open | accepted | false_positive
    decision: (
        Decision | None
    )  # what somebody decided; for an acceptance that lapsed, status is open


def _sentence(rule: Rule, values: Mapping[str, str]) -> str:
    """The rule's message with its parameters filled in; its title when they do not fit."""
    if not set(PLACEHOLDER.findall(rule.summary)) <= set(values):
        return _(rule.title)
    try:
        return _(rule.summary, **values)
    except (KeyError, ValueError, TypeError):  # a translation that uses other names
        return _(rule.title)


def _host_uuids(params: Mapping[str, Any]) -> list[uuid.UUID]:
    """The hosts an address-level finding lists (stored as text; unreadable ones are skipped)."""
    found: list[uuid.UUID] = []
    for raw in params.get("host_ids") or []:
        try:
            found.append(uuid.UUID(str(raw)))
        except ValueError:
            continue
    return found


def _scope(finding: Finding) -> str:
    if finding.host_id is not None:
        return "host"
    return "domain" if finding.attribution == "domain" else "address"


def _evidence(finding: Finding, rule: Rule, host_ids: Sequence[uuid.UUID]) -> EvidenceLink | None:
    if not rule.checks:
        return None
    check = rule.checks[0]
    if finding.host_id is not None:
        return EvidenceLink(finding.host_id, check)
    if finding.attribution == "domain":
        return EvidenceLink(None, check)
    return EvidenceLink(host_ids[0], check) if host_ids else None  # the address as one host saw it


def _facts(rule: Rule, params: Mapping[str, Any]) -> list[tuple[str, str]]:
    facts: list[tuple[str, str]] = []
    for key, label in rule.labels.items():
        if params.get(key) in (None, "", []):
            continue
        value = render_value(key, params[key])
        listed = len(params[key]) if isinstance(params[key], list) else 0
        if key == "hosts" and int(params.get("host_count") or 0) > listed:
            value += " " + _("and %(count)s more", count=int(params["host_count"]) - listed)
        facts.append((_(label), value))
    return facts[:MAX_SHOWN_FACTS]


def describe(
    finding: Finding,
    hostnames: Mapping[uuid.UUID, str] | None = None,
    decision: Decision | None = None,
) -> FindingView:
    """A stored finding in words. A rule that no longer exists still shows what was stored.

    ``decision`` is what somebody decided about it, if anybody did."""
    rule = RULES.get(finding.rule_id)
    params: dict[str, Any] = dict(finding.params or {})
    scope = _scope(finding)
    values = {key: render_value(key, value) for key, value in params.items()}
    return FindingView(
        id=finding.id,
        rule_id=finding.rule_id,
        title=_(rule.title) if rule else finding.rule_id,
        message=_sentence(rule, values) if rule else "",
        advice=_(rule.advice) if rule else "",
        severity=finding.severity,
        confidence=finding.confidence,
        attribution=finding.attribution,
        subject=finding.subject,
        scope=scope,
        host_id=finding.host_id,
        hostname=(hostnames or {}).get(finding.host_id) if finding.host_id else None,
        address=str(params["ip"]) if scope == "address" and params.get("ip") else None,
        facts=_facts(rule, params) if rule else [],
        evidence=_evidence(finding, rule, _host_uuids(params)) if rule else None,
        status=decision.status if decision and not decision.lapsed else OPEN,
        decision=decision,
    )


def hostnames_for(session: Session, findings: Sequence[Finding]) -> dict[uuid.UUID, str]:
    """Hostnames of the hosts the findings are about (one query)."""
    ids: set[uuid.UUID] = set()
    for finding in findings:
        if finding.host_id is not None:
            ids.add(finding.host_id)
        ids.update(_host_uuids(finding.params or {}))
    if not ids:
        return {}
    return dict(session.execute(select(Host.id, Host.hostname).where(Host.id.in_(ids))).all())


def describe_all(
    session: Session,
    findings: Sequence[Finding],
    assessment_id: uuid.UUID,
    *,
    today: date | None = None,
) -> list[FindingView]:
    """Findings in words, with the decisions about them (two queries for the whole list)."""
    names = hostnames_for(session, findings)
    decisions = load_decisions(
        session, assessment_id, {f.fingerprint for f in findings}, today or utc_now().date()
    )
    return [describe(f, names, decisions.get(f.fingerprint)) for f in findings]


# --------------------------------------------------------------------------- for the pages

MAX_HOST_OPTIONS = 500  # hosts offered by the host filter of the findings page


def evaluation_info(scan: Scan) -> Mapping[str, Any]:
    """What ``evaluate_scan`` recorded on the scan (empty when it never ran)."""
    info = (scan.summary or {}).get("findings")
    return info if isinstance(info, dict) else {}


def evaluation_state(scan: Scan) -> str:
    """``pending`` while the scan runs; once it ended: ``ready``, ``failed`` or ``not_evaluated``
    (cancelled scans, and scans from before rules existed)."""
    if not scan.is_terminal:
        return "pending"
    info = evaluation_info(scan)
    if info.get("error"):
        return "failed"
    return "ready" if "total" in info else "not_evaluated"


@dataclass(frozen=True)
class FindingsSummary:
    """What a scan's findings add up to: the findings panel of the assessment page and the
    tabs and filters of the findings page. Counts without a status are the open findings."""

    state: str
    breakdown: Breakdown
    errors: list[str]  # ids of rules that crashed: their findings are missing
    dropped: int  # findings beyond the per-scan cap

    @property
    def total(self) -> int:
        """Every finding, whatever its status."""
        return self.breakdown.total("all")

    @property
    def open_total(self) -> int:
        return self.breakdown.total(OPEN)

    @property
    def by_severity(self) -> dict[str, int]:
        return self.breakdown.by_severity(OPEN)

    @property
    def rules(self) -> list[RuleCount]:
        return self.breakdown.rules(OPEN)

    @property
    def accepted(self) -> int:
        return self.breakdown.total(ACCEPTED)

    @property
    def false_positive(self) -> int:
        return self.breakdown.total(FALSE_POSITIVE)


def findings_summary(session: Session, scan: Scan, *, today: date | None = None) -> FindingsSummary:
    state = evaluation_state(scan)
    if state != "ready":
        return FindingsSummary(state, Breakdown({}), [], 0)
    info = evaluation_info(scan)
    return FindingsSummary(
        state=state,
        breakdown=breakdown(session, scan, today=today),
        errors=[str(rule) for rule in info.get("errors", [])],
        dropped=int(info.get("dropped", 0)),
    )


@dataclass(frozen=True)
class FindingsListing:
    """One page of the findings of a scan, filtered, with the summary the filters are built from."""

    summary: FindingsSummary
    page: FindingPage
    items: list[FindingView]
    hosts: list[tuple[uuid.UUID, str]]  # what the host filter offers


def host_options(session: Session, scan: Scan) -> list[tuple[uuid.UUID, str]]:
    """The hosts of the scan by name, bounded."""
    rows = session.execute(
        select(Host.id, Host.hostname)
        .where(Host.scan_id == scan.id)
        .order_by(Host.hostname)
        .limit(MAX_HOST_OPTIONS)
    )
    return [(host_id, hostname) for host_id, hostname in rows]


def findings_listing(
    session: Session,
    scan: Scan,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    host_id: uuid.UUID | None = None,
    status: str = OPEN,
    page: int = 1,
    per_page: int = 50,
    today: date | None = None,
) -> FindingsListing:
    summary = findings_summary(session, scan, today=today)
    if summary.state != "ready":
        return FindingsListing(summary, FindingPage([], 0, 1, per_page), [], [])
    found = list_findings(
        session,
        scan,
        severity=severity,
        rule_id=rule_id,
        host_id=host_id,
        status=status,
        page=page,
        per_page=per_page,
        today=today,
    )
    return FindingsListing(
        summary,
        found,
        describe_all(session, found.rows, scan.assessment_id, today=today),
        host_options(session, scan),
    )


@dataclass(frozen=True)
class HostFindings:
    """The findings on a host's page: its own, and those about the addresses it resolves to.
    Open ones come first."""

    state: str
    own: list[FindingView]
    on_addresses: list[FindingView]


def host_findings(
    session: Session, scan: Scan, host_id: uuid.UUID, *, today: date | None = None
) -> HostFindings:
    state = evaluation_state(scan)
    if state != "ready":
        return HostFindings(state, [], [])
    current = current_status(today or utc_now().date())

    def fetch(condition: Any) -> list[Finding]:
        query = with_decisions(select(Finding), scan.assessment_id).where(condition)
        return list(session.scalars(_in_order(query, current)))

    own = fetch(and_(Finding.scan_id == scan.id, Finding.host_id == host_id))
    addresses = sorted(_addresses_by_host(session, scan.id, [host_id]).get(host_id, set()))
    shared = fetch(_on_addresses(scan.id, addresses)) if addresses else []
    return HostFindings(
        state=state,
        own=describe_all(session, own, scan.assessment_id, today=today),
        on_addresses=describe_all(session, shared, scan.assessment_id, today=today),
    )


@dataclass(frozen=True)
class HostSummary:
    """The hosts table's cell: how many open findings, and the most serious severity among them."""

    count: int
    top: str


def host_summaries(
    session: Session,
    scan: Scan,
    host_ids: Sequence[uuid.UUID],
    *,
    today: date | None = None,
) -> dict[uuid.UUID, HostSummary]:
    """Open findings per host (its own and those on its addresses) for the hosts of one page."""
    wanted = list(host_ids)
    if not wanted:
        return {}
    current = current_status(today or utc_now().date())

    def open_findings(*columns: Any) -> Any:
        return with_decisions(select(*columns).select_from(Finding), scan.assessment_id).where(
            Finding.scan_id == scan.id, current == OPEN
        )

    severities: dict[uuid.UUID, list[str]] = {}
    for own_host, severity in session.execute(
        open_findings(Finding.host_id, Finding.severity).where(Finding.host_id.in_(wanted))
    ):
        if own_host is not None:
            severities.setdefault(own_host, []).append(severity)
    by_address: dict[str, list[str]] = {}
    for address, severity in session.execute(
        open_findings(Finding.params["ip"].astext, Finding.severity).where(
            Finding.host_id.is_(None),
            Finding.attribution != "domain",
            Finding.params.has_key("ip"),
        )
    ):
        by_address.setdefault(address, []).append(severity)
    if by_address:
        for host_id, addresses in _addresses_by_host(session, scan.id, wanted).items():
            for address in sorted(addresses):
                severities.setdefault(host_id, []).extend(by_address.get(address, []))
    return {
        host_id: HostSummary(count=len(found), top=min(found, key=SEVERITIES.index))
        for host_id, found in severities.items()
        if found
    }
