"""Scan lifecycle: start, expand discovery into hosts, progress, host listing, completion."""

from __future__ import annotations

import logging
import math
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY, Check, checks_with_scope
from app.config import MAX_HOSTS_CEILING
from app.models import Assessment, CheckResult, Host, Scan, User
from app.models.base import utc_now
from app.models.scan import COMPARABLE_SCAN_STATUSES
from app.service import audit as audit_service
from app.service import findings as findings_service
from app.service import summary as summary_service
from app.service.host_view import CheckCell, DomainRow, domain_rows, host_cells

log = logging.getLogger(__name__)

OPEN_CHECK_STATUSES = ("queued", "running")
PROBLEM_CHECK_STATUSES = ("error", "unavailable")
ACTIVE_SCAN_STATUSES = ("queued", "running")


class ScanInProgressError(Exception):
    """A scan for this assessment is still queued or running."""

    def __init__(self, scan: Scan) -> None:
        super().__init__("A scan is already in progress for this assessment.")
        self.scan = scan


class ScanRateLimitError(Exception):
    """The person has started as many scans in the last hour as they may."""

    def __init__(self, limit: int, retry_after: timedelta) -> None:
        super().__init__(f"At most {limit} scans an hour per person.")
        self.limit = limit
        self.retry_after = retry_after  # until the oldest scan of the hour is an hour old


SCAN_RATE_WINDOW = timedelta(hours=1)
DEFAULT_MAX_HOSTS = 200  # for a scan that recorded no cap


# --------------------------------------------------------------------------- queries


def get_active_scan(session: Session, assessment_id: Any) -> Scan | None:
    """The queued or running scan of an assessment, if any."""
    return session.scalar(
        select(Scan)
        .where(Scan.assessment_id == assessment_id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
        .order_by(Scan.created_at.desc())
        .limit(1)
    )


def get_latest_scan(session: Session, assessment_id: Any) -> Scan | None:
    """The most recent scan of an assessment, whatever its state."""
    return session.scalar(
        select(Scan)
        .where(Scan.assessment_id == assessment_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )


# --------------------------------------------------------------------------- start


def start_scan(
    session: Session, assessment: Assessment, user: User, config: Mapping[str, Any]
) -> Scan:
    """Create a queued scan whose first task is discovery. The caller commits.

    The options record what this scan was configured with, so an old scan stays explainable
    after the configuration or the manual host list changed.
    """
    active = get_active_scan(session, assessment.id)
    if active is not None:
        raise ScanInProgressError(active)
    _check_scan_rate(session, user, int(config.get("MAX_SCANS_PER_USER_PER_HOUR", 0)))
    # The host cap is read once here and stays with the scan: it is what the scan is planned by.
    max_hosts = min(int(config["MAX_HOSTS_PER_RUN"]), MAX_HOSTS_CEILING)
    scan = Scan(
        assessment_id=assessment.id,
        requested_by=user.id,
        status="queued",
        options={
            "max_hosts": max_hosts,
            "ct_mode": str(config["CT_MODE"]),
            "ct_sources": list(config["CT_SOURCES"]),
            "manual_hosts": list(assessment.manual_hosts),
        },
    )
    try:
        # A savepoint, so losing a race to a simultaneous request leaves the session usable.
        with session.begin_nested():
            session.add(scan)
            session.flush()
    except IntegrityError:
        winner = get_active_scan(session, assessment.id)
        if winner is None:
            raise
        raise ScanInProgressError(winner) from None
    session.add(CheckResult(scan_id=scan.id, host_id=None, check_key=DISCOVERY_KEY))
    session.flush()
    audit_service.record(
        session,
        "scan.started",
        actor=user,
        assessment=assessment,
        subject=str(scan.id),
        details={"max_hosts": max_hosts, "manual_hosts": len(assessment.manual_hosts)},
    )
    return scan


def _check_scan_rate(session: Session, user: User, limit: int) -> None:
    """Refuse a scan when the person has started ``limit`` of them in the last hour (0: no limit).

    A soft limit: two requests at the same instant can both pass. It is there to stop a script or
    a stolen session from loading the targets, the providers and the worker, not to count exactly.
    """
    if limit <= 0:
        return
    now = utc_now()
    recent = list(
        session.scalars(
            select(Scan.created_at)
            .where(Scan.requested_by == user.id, Scan.created_at > now - SCAN_RATE_WINDOW)
            .order_by(Scan.created_at)
        )
    )
    if len(recent) >= limit:
        # The scan that has to leave the hour before there is room again.
        raise ScanRateLimitError(limit, recent[len(recent) - limit] + SCAN_RATE_WINDOW - now)


# --------------------------------------------------------------------------- discovery -> hosts


@dataclass(frozen=True)
class HostSeed:
    """A host to create for a scan, and where it came from."""

    hostname: str
    source: str
    ct_sources: tuple[str, ...] = ()
    first_seen: datetime | None = None
    last_seen: datetime | None = None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def host_cap(options: Mapping[str, Any]) -> int:
    """How many hosts the scan may review: what it was started with, at least one and never more
    than the ceiling. This is the number the scan is planned by, whatever was stored."""
    try:
        wanted = int(options.get("max_hosts", DEFAULT_MAX_HOSTS))
    except (TypeError, ValueError):
        wanted = DEFAULT_MAX_HOSTS
    return max(1, min(wanted, MAX_HOSTS_CEILING))


def plan_hosts(
    domain: str,
    discovery_data: Mapping[str, Any],
    discovery_ok: bool,
    manual_hosts: Sequence[str],
    max_hosts: int,
) -> tuple[list[HostSeed], int]:
    """Decide which hosts a scan reviews, in priority order, and how many the cap dropped.

    Order: the apex (always reviewed, even when no certificate names it), the hosts an analyst
    added by hand, then what CT found (already ordered by recency). When every CT source failed,
    ``www`` is added as a labelled fallback. The cap applies to the whole list.
    """
    ct_hosts: dict[str, dict[str, Any]] = {
        str(row["hostname"]): row for row in discovery_data.get("hosts", [])
    }
    manual = set(manual_hosts)
    wanted = [domain, *manual_hosts, *ct_hosts]
    if not discovery_ok:
        wanted.append(f"www.{domain}")

    seeds: list[HostSeed] = []
    seen: set[str] = set()
    for hostname in wanted:
        if hostname in seen:
            continue
        seen.add(hostname)
        row = ct_hosts.get(hostname)
        if row is not None:
            seeds.append(
                HostSeed(
                    hostname,
                    "ct",
                    tuple(row.get("sources", [])),
                    _parse_time(row.get("first_seen")),
                    _parse_time(row.get("last_seen")),
                )
            )
        elif hostname in manual:
            seeds.append(HostSeed(hostname, "manual"))
        elif hostname == domain:
            seeds.append(HostSeed(hostname, "apex"))
        else:
            seeds.append(HostSeed(hostname, "fallback"))
    return seeds[:max_hosts], max(0, len(seeds) - max_hosts)


def apply_discovery(
    session: Session,
    scan: Scan,
    discovery: CheckResult,
    registry: Mapping[str, Check] | None = None,
) -> int:
    """Create the scan's hosts from a finished discovery and queue every other check.

    Runs in the transaction that stores the discovery outcome, so a scan never has a finished
    discovery without its hosts. ``registry`` defaults to the application's checks. Returns the
    number of hosts created.
    """
    assessment = session.get(Assessment, scan.assessment_id)
    if assessment is None:
        raise LookupError("The scan's assessment no longer exists.")
    seeds, dropped = plan_hosts(
        assessment.domain,
        discovery.data,
        discovery.status == "ok",
        list(scan.options.get("manual_hosts", [])),
        host_cap(scan.options),
    )
    host_checks = checks_with_scope("host", registry)
    for seed in seeds:
        host = Host(
            scan_id=scan.id,
            hostname=seed.hostname,
            source=seed.source,
            ct_sources=list(seed.ct_sources),
            first_seen=seed.first_seen,
            last_seen=seed.last_seen,
        )
        session.add(host)
        session.flush()
        for check in host_checks:
            session.add(CheckResult(scan_id=scan.id, host_id=host.id, check_key=check.key))
    for check in checks_with_scope("domain", registry):
        if check.key != DISCOVERY_KEY:
            session.add(CheckResult(scan_id=scan.id, host_id=None, check_key=check.key))
    discovery.data = {
        **discovery.data,
        "planned": {"hosts": len(seeds), "dropped_by_cap": dropped},
    }
    session.flush()
    return len(seeds)


# --------------------------------------------------------------------------- progress


@dataclass(frozen=True)
class ScanProgress:
    """Counts shown while a scan runs."""

    status: str
    hosts: int
    checks_total: int
    checks_open: int
    checks_problem: int

    @property
    def checks_done(self) -> int:
        return self.checks_total - self.checks_open

    @property
    def percent(self) -> int:
        return 100 if self.checks_total == 0 else int(100 * self.checks_done / self.checks_total)


def scan_progress(session: Session, scan: Scan) -> ScanProgress:
    """Hosts and check counts of a scan."""
    counts = dict(
        session.execute(
            select(CheckResult.status, func.count())
            .where(CheckResult.scan_id == scan.id)
            .group_by(CheckResult.status)
        ).all()
    )
    hosts = session.scalar(select(func.count()).select_from(Host).where(Host.scan_id == scan.id))
    return ScanProgress(
        status=scan.status,
        hosts=hosts or 0,
        checks_total=sum(counts.values()),
        checks_open=sum(counts.get(status, 0) for status in OPEN_CHECK_STATUSES),
        checks_problem=sum(counts.get(status, 0) for status in PROBLEM_CHECK_STATUSES),
    )


def get_discovery(session: Session, scan: Scan) -> CheckResult | None:
    """The discovery result of a scan (its record of what each CT source reported)."""
    return session.scalar(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id,
            CheckResult.host_id.is_(None),
            CheckResult.check_key == DISCOVERY_KEY,
        )
    )


# --------------------------------------------------------------------------- hosts


@dataclass(frozen=True)
class HostPage:
    """One page of hosts of a scan."""

    rows: list[Host]
    total: int
    page: int
    per_page: int

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / self.per_page))


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


HOST_STATES = ("all", "problems", "pending")


def _with_check_in(statuses: Sequence[str]) -> Any:
    """SQL condition: the host has at least one check in one of these statuses."""
    return (
        select(CheckResult.id)
        .where(CheckResult.host_id == Host.id, CheckResult.status.in_(list(statuses)))
        .exists()
    )


def list_hosts(
    session: Session,
    scan_id: Any,
    *,
    query: str = "",
    page: int = 1,
    per_page: int = 50,
    state: str = "all",
) -> HostPage:
    """Hosts of a scan, filtered and paged in SQL.

    ``query``: a hostname fragment. ``state``: ``problems`` keeps hosts with a check that failed
    or was unavailable, ``pending`` those with a check still queued or running.
    """
    page = max(1, page)
    per_page = max(1, min(per_page, 100))
    stmt = select(Host).where(Host.scan_id == scan_id)
    if query.strip():
        stmt = stmt.where(
            Host.hostname.ilike(f"%{_escape_like(query.strip().lower())}%", escape="\\")
        )
    if state == "problems":
        stmt = stmt.where(_with_check_in(PROBLEM_CHECK_STATUSES))
    elif state == "pending":
        stmt = stmt.where(_with_check_in(OPEN_CHECK_STATUSES))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(
        session.scalars(stmt.order_by(Host.hostname).limit(per_page).offset((page - 1) * per_page))
    )
    return HostPage(rows=rows, total=total, page=page, per_page=per_page)


# --------------------------------------------------------------------------- completion


def cancel_active_scan(session: Session, assessment_id: Any) -> bool:
    """Cancel the queued or running scan of an assessment; the caller commits.

    Queued checks are skipped (reason ``scan_cancelled``). Checks that already run finish and
    keep their results, but no further host tasks are created. Returns whether a scan was
    cancelled.
    """
    scan: Scan | None = session.scalar(
        select(Scan)
        .where(Scan.assessment_id == assessment_id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
        .with_for_update()
    )
    if scan is None:
        return False
    now = utc_now()
    session.execute(
        update(CheckResult)
        .where(CheckResult.scan_id == scan.id, CheckResult.status == "queued")
        .values(status="skipped", reason_code="scan_cancelled", collected_at=now)
    )
    scan.status = "cancelled"
    scan.finished_at = now
    audit_service.record(session, "scan.cancelled", assessment=assessment_id, subject=str(scan.id))
    return True


def finalize_scan_if_done(
    session: Session, scan_id: Any, config: Mapping[str, Any] | None = None
) -> Scan | None:
    """Mark the scan finished once no check is queued or running.

    The scan row is locked first: when the last two checks finish at the same moment, the one
    that locks second sees the other's committed result and finalises; neither can miss it.
    Call this after persisting a check outcome, in the same transaction.
    """
    scan: Scan | None = session.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
    if scan is None or scan.is_terminal:
        return scan
    open_checks = session.scalar(
        select(func.count())
        .select_from(CheckResult)
        .where(CheckResult.scan_id == scan_id, CheckResult.status.in_(OPEN_CHECK_STATUSES))
    )
    if open_checks:
        return scan
    problems = session.scalar(
        select(func.count())
        .select_from(CheckResult)
        .where(CheckResult.scan_id == scan_id, CheckResult.status.in_(PROBLEM_CHECK_STATUSES))
    )
    scan.status = "partial" if problems else "completed"
    scan.finished_at = utc_now()
    if config is not None:
        _evaluate_rules(session, scan, config)
    return scan


def _evaluate_rules(session: Session, scan: Scan, config: Mapping[str, Any]) -> None:
    """Turn the finished scan's results into findings; a failure here never fails the scan."""
    try:
        with session.begin_nested():  # a savepoint: a database error loses the findings only
            findings_service.evaluate_scan(session, scan, config)
    except Exception:
        log.exception("evaluating the rules of scan %s failed", scan.id)
        scan.summary = {**(scan.summary or {}), "findings": {"error": "evaluation_failed"}}


# --------------------------------------------------------------------------- overview for the UI


@dataclass(frozen=True)
class SourceLine:
    """How one CT source did, for display."""

    source: str
    status: str
    reason: str | None
    names: int
    pages: int
    truncated: bool


@dataclass(frozen=True)
class ScanOverview:
    """Everything the assessment page shows about a scan."""

    scan: Scan
    progress: ScanProgress
    sources: list[SourceLine]
    wildcard_patterns: list[str]
    names_seen: int
    out_of_scope: int
    dropped_by_cap: int
    discovery_status: str | None
    waiting_for_worker: bool
    hosts: HostPage
    host_cells: dict[Any, dict[str, CheckCell]]
    ip_data_missing: bool  # the location databases are not installed (or unreadable)
    domain_rows: list[DomainRow]
    findings: findings_service.FindingsSummary
    host_findings: dict[Any, findings_service.HostSummary]
    summary: summary_service.ScanSummary | None  # once the scan is over
    previous_scan_id: uuid.UUID | None  # the scan to compare this one with (it ran before it)

    @property
    def is_active(self) -> bool:
        return self.scan.status in ACTIVE_SCAN_STATUSES

    @property
    def discovery_failed(self) -> bool:
        return self.discovery_status in PROBLEM_CHECK_STATUSES

    @property
    def coverage_gaps(self) -> list[SourceLine]:
        """Sources that did not deliver everything although discovery as a whole succeeded.

        (When every source failed, ``discovery_failed`` says so; this is for the quieter case
        where the host list looks complete but a source was missing or cut short.)
        """
        if self.discovery_status != "ok":
            return []
        return [line for line in self.sources if line.status != "ok" or line.truncated]


WAITING_FOR_WORKER_AFTER = timedelta(seconds=10)


def previous_scan_id(session: Session, scan: Scan) -> uuid.UUID | None:
    """The scan to compare this one with: the one that ran to the end just before it. ``None`` when
    this scan did not run to the end itself (what it lacks is not a change) or is the first."""
    if scan.status not in COMPARABLE_SCAN_STATUSES:
        return None
    return session.scalar(
        select(Scan.id)
        .where(
            Scan.assessment_id == scan.assessment_id,
            Scan.status.in_(COMPARABLE_SCAN_STATUSES),
            tuple_(Scan.created_at, Scan.id) < tuple_(scan.created_at, scan.id),
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


def scan_overview(
    session: Session,
    scan: Scan,
    *,
    query: str = "",
    page: int = 1,
    per_page: int = 50,
    state: str = "all",
    config: Mapping[str, Any] | None = None,
) -> ScanOverview:
    """Gather progress, discovery notes and one page of hosts for the scan panel.

    ``config`` supplies the allowed area of the summary (the default area when it is left out)."""
    discovery = get_discovery(session, scan)
    data: Mapping[str, Any] = discovery.data if discovery else {}
    counts: Mapping[str, Any] = data.get("counts", {})
    sources = [
        SourceLine(
            source=str(item.get("source", "")),
            status=str(item.get("status", "")),
            reason=item.get("reason_code"),
            names=int(item.get("names", 0)),
            pages=int(item.get("pages", 0)),
            truncated=bool(item.get("truncated", False)),
        )
        for item in data.get("sources", [])
    ]
    hosts = list_hosts(session, scan.id, query=query, page=page, per_page=per_page, state=state)
    findings = findings_service.findings_summary(session, scan)
    return ScanOverview(
        scan=scan,
        progress=scan_progress(session, scan),
        sources=sources,
        wildcard_patterns=list(data.get("wildcard_patterns", [])),
        names_seen=int(counts.get("names_seen", 0)),
        out_of_scope=int(counts.get("out_of_scope", 0)),
        dropped_by_cap=summary_service.hosts_over_limit(data),
        discovery_status=discovery.status if discovery else None,
        waiting_for_worker=scan.status == "queued"
        and utc_now() - scan.created_at > WAITING_FOR_WORKER_AFTER,
        hosts=hosts,
        host_cells=host_cells(session, [host.id for host in hosts.rows]),
        domain_rows=domain_rows(session, scan.id),
        findings=findings,
        summary=(
            summary_service.build_summary(
                session, scan, data, findings_service.allowed_countries(config or {})
            )
            if scan.is_terminal
            else None
        ),
        previous_scan_id=previous_scan_id(session, scan),
        host_findings=(
            findings_service.host_summaries(session, scan, [host.id for host in hosts.rows])
            if findings.state == "ready"
            else {}
        ),
        ip_data_missing=session.scalar(
            select(CheckResult.id)
            .where(
                CheckResult.scan_id == scan.id,
                CheckResult.check_key == "ip",
                CheckResult.reason_code.in_(("datasets_missing", "datasets_unreadable")),
            )
            .limit(1)
        )
        is not None,
    )
