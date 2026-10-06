"""The scans of an assessment over time, and what changed between two of them.

A re-scan creates a new scan and the old one stays as it was (a finished scan is never modified), so
history costs nothing to keep. Hosts are matched by name and findings by fingerprint (rule and
subject). The comparison claims only what the stored results can bear:

- a finding is **resolved** when every check it rested on answered again in the newer scan and the
  rule no longer fires; when one of them did not run, failed or gave no answer, the finding is
  **not re-checked** and says why, because "not looked at" is not "fixed";
- a host that is missing from the newer scan may only be missing because discovery was incomplete,
  and the comparison says so when it was.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY
from app.models import Assessment, CheckResult, Finding, Host, Scan, User
from app.models.base import utc_now
from app.models.scan import COMPARABLE_SCAN_STATUSES, TERMINAL_SCAN_STATUSES
from app.service import findings as findings_service
from app.service.decisions import ACCEPTED, FALSE_POSITIVE, load_decisions
from app.service.findings import SEVERITIES, FindingView
from app.service.scans import get_discovery
from app.service.summary import hosts_over_limit

MAX_SCANS_LISTED = 50  # the history page lists this many, newest first
MAX_LISTED = 100  # findings or hosts listed per group of a comparison; the counts are complete
DEFINITIVE = ("ok", "no_data")  # a check that answered: it found something, or found nothing
CHUNK = 1_000  # ids per query (the driver allows far more; this keeps statements small)
CT_SOURCE_NAMES = {"ctlogs": "ctlogs.dev", "certspotter": "CertSpotter", "crtsh": "crt.sh"}


# --------------------------------------------------------------------------- the list


@dataclass(frozen=True)
class ScanRow:
    """One scan of the history: who started it, how long it took, what it found."""

    scan: Scan
    started_by: str
    hosts: int
    findings: int | None  # None: the scan was not evaluated (cancelled, or from before the rules)
    serious: int | None  # critical and high ones, of those
    duration: timedelta | None
    previous: uuid.UUID | None  # the scan to compare this one with: the one that ran before it


def list_scans(
    session: Session, assessment_id: uuid.UUID, *, limit: int = MAX_SCANS_LISTED
) -> list[ScanRow]:
    """The scans of an assessment, newest first. The findings are what each scan stored when it
    ended, before anybody decided anything about them."""
    hosts = (
        select(func.count(Host.id)).where(Host.scan_id == Scan.id).correlate(Scan).scalar_subquery()
    )
    rows = session.execute(
        select(Scan, User.email, hosts)
        .join(User, User.id == Scan.requested_by)
        .where(Scan.assessment_id == assessment_id)
        .order_by(Scan.created_at.desc(), Scan.id)
        .limit(max(1, limit))
    ).all()
    ran = [scan.id for scan, _email, _hosts in rows if scan.status in COMPARABLE_SCAN_STATUSES]
    result: list[ScanRow] = []
    for scan, email, host_count in rows:
        info = findings_service.evaluation_info(scan)
        ready = findings_service.evaluation_state(scan) == "ready"
        levels: Mapping[str, Any] = info.get("by_severity") or {}
        position = ran.index(scan.id) if scan.status in COMPARABLE_SCAN_STATUSES else -1
        result.append(
            ScanRow(
                scan=scan,
                started_by=email,
                hosts=int(host_count or 0),
                findings=int(info.get("total", 0)) if ready else None,
                serious=int(levels.get("critical", 0)) + int(levels.get("high", 0))
                if ready
                else None,
                duration=(
                    scan.finished_at - scan.started_at
                    if scan.finished_at and scan.started_at
                    else None
                ),
                previous=ran[position + 1] if 0 <= position < len(ran) - 1 else None,
            )
        )
    return result


def get_scan(session: Session, assessment_id: uuid.UUID, scan_id: uuid.UUID) -> Scan | None:
    """A scan of this assessment (``None`` for one that belongs to another)."""
    return session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.assessment_id == assessment_id)
    )


def finished_scans(session: Session, assessment_id: uuid.UUID) -> list[Scan]:
    """The scans that ended, newest first: the ones a comparison can use."""
    return list(
        session.scalars(
            select(Scan)
            .where(Scan.assessment_id == assessment_id, Scan.status.in_(TERMINAL_SCAN_STATUSES))
            .order_by(Scan.created_at.desc(), Scan.id)
            .limit(MAX_SCANS_LISTED)
        )
    )


def default_pair(scans: Sequence[Scan]) -> tuple[Scan, Scan] | None:
    """(older, newer): the two newest scans that ran to the end, or ``None`` with fewer than two."""
    ran = [scan for scan in scans if scan.status in COMPARABLE_SCAN_STATUSES]
    return (ran[1], ran[0]) if len(ran) >= 2 else None


def in_order(first: Scan, second: Scan) -> tuple[Scan, Scan]:
    """(older, newer), whichever way round they were asked for."""
    return (
        (first, second)
        if (first.created_at, first.id) <= (second.created_at, second.id)
        else (second, first)
    )


# --------------------------------------------------------------------------- the comparison


@dataclass(frozen=True)
class HostRef:
    id: uuid.UUID
    hostname: str


@dataclass(frozen=True)
class Gap:
    """Why a finding of the older scan could not be judged in the newer one: the check that did not
    answer again (``status`` is None when the newer scan has no such check, e.g. no such host)."""

    check: str | None
    hostname: str | None
    status: str | None
    reason: str | None


@dataclass(frozen=True)
class Changed:
    finding: FindingView  # as the newer scan has it
    was: str  # the severity it had in the older scan


@dataclass(frozen=True)
class Unclear:
    finding: FindingView  # as the older scan had it
    gap: Gap


@dataclass(frozen=True)
class DiscoveryGaps:
    """What may have kept hosts out of a scan: sources that did not deliver, and the host limit."""

    sources: tuple[str, ...]  # names of sources that failed or were cut short
    over_limit: int  # hosts beyond the limit per scan

    def __bool__(self) -> bool:
        return bool(self.sources or self.over_limit)


@dataclass(frozen=True)
class Comparison:
    older: Scan
    newer: Scan
    hosts_added: tuple[HostRef, ...]
    hosts_added_total: int
    hosts_removed: tuple[HostRef, ...]
    hosts_removed_total: int
    hosts_kept: int
    older_gaps: DiscoveryGaps  # hosts "added" may only be hosts the older scan missed
    newer_gaps: DiscoveryGaps  # hosts "removed" may only be hosts the newer scan missed
    findings_state: tuple[str, str]  # evaluation state of (older, newer)
    rules_differ: bool  # judged by different rule sets: a finding may come or go because a rule did
    findings_dropped: tuple[int, int]  # findings each scan could not keep (beyond its limit)
    new: tuple[FindingView, ...]
    new_total: int
    resolved: tuple[FindingView, ...]
    resolved_total: int
    changed: tuple[Changed, ...]
    changed_total: int
    unclear: tuple[Unclear, ...]
    unclear_total: int
    unchanged: int
    unchanged_decided: int  # of those, accepted or marked as false positives (decisions carry over)

    @property
    def findings_comparable(self) -> bool:
        return self.findings_state == ("ready", "ready")


def _count(value: object) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0


def _severity_key(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _hosts(session: Session, scan: Scan) -> dict[str, HostRef]:
    rows = session.execute(select(Host.id, Host.hostname).where(Host.scan_id == scan.id))
    return {hostname: HostRef(host_id, hostname) for host_id, hostname in rows}


def discovery_gaps(session: Session, scan: Scan) -> DiscoveryGaps:
    """The discovery sources that failed or were cut short, and the hosts over the limit."""
    row = get_discovery(session, scan)
    data: Mapping[str, Any] = row.data if row is not None and isinstance(row.data, dict) else {}
    names = [
        CT_SOURCE_NAMES.get(str(entry.get("source")), str(entry.get("source")))
        for entry in data.get("sources", [])
        if isinstance(entry, dict) and (entry.get("status") != "ok" or entry.get("truncated"))
    ]
    return DiscoveryGaps(tuple(names), hosts_over_limit(data))


def _chunks(values: Sequence[Any]) -> list[Sequence[Any]]:
    return [values[i : i + CHUNK] for i in range(0, len(values), CHUNK)]


def _evidence_of(
    session: Session, findings: Sequence[Finding]
) -> dict[str, tuple[str, uuid.UUID | None]]:
    """For the check results the findings rest on: (check, host) by result id."""
    ids: list[uuid.UUID] = []
    for finding in findings:
        for raw in finding.evidence or []:
            try:
                ids.append(uuid.UUID(str(raw)))
            except ValueError:
                continue
    found: dict[str, tuple[str, uuid.UUID | None]] = {}
    for chunk in _chunks(sorted(set(ids))):
        rows = session.execute(
            select(CheckResult.id, CheckResult.check_key, CheckResult.host_id).where(
                CheckResult.id.in_(chunk)
            )
        )
        found.update({str(row_id): (check, host_id) for row_id, check, host_id in rows})
    return found


def _answers(session: Session, scan: Scan) -> dict[tuple[str | None, str], tuple[str, str | None]]:
    """What each check of the scan said: (host name or None, check) -> (status, reason)."""
    rows = session.execute(
        select(Host.hostname, CheckResult.check_key, CheckResult.status, CheckResult.reason_code)
        .select_from(CheckResult)
        .outerjoin(Host, Host.id == CheckResult.host_id)
        .where(CheckResult.scan_id == scan.id, CheckResult.check_key != DISCOVERY_KEY)
    )
    return {(hostname, check): (status, reason) for hostname, check, status, reason in rows}


def _gap(
    finding: Finding,
    evidence: Mapping[str, tuple[str, uuid.UUID | None]],
    older_names: Mapping[uuid.UUID, str],
    answers: Mapping[tuple[str | None, str], tuple[str, str | None]],
) -> Gap | None:
    """The first check the finding rested on that did not answer again; ``None`` when all did."""
    if not finding.evidence:
        return Gap(None, None, None, None)  # nothing recorded to judge by
    for raw in finding.evidence:
        known = evidence.get(str(raw))
        if known is None:
            return Gap(None, None, None, None)
        check, host_id = known
        hostname = older_names.get(host_id) if host_id is not None else None
        answer = answers.get((hostname, check))
        if answer is None:
            return Gap(check, hostname, None, None)
        if answer[0] not in DEFINITIVE:
            return Gap(check, hostname, answer[0], answer[1])
    return None


def _ordered(views: Sequence[FindingView]) -> list[FindingView]:
    return sorted(views, key=lambda v: (_severity_key(v.severity), v.title, v.subject))


def compare(
    session: Session,
    assessment: Assessment,
    older: Scan,
    newer: Scan,
    *,
    today: date | None = None,
) -> Comparison:
    """What changed from ``older`` to ``newer`` (two finished scans of ``assessment``)."""
    day = today or utc_now().date()
    states = (findings_service.evaluation_state(older), findings_service.evaluation_state(newer))

    before, after = _hosts(session, older), _hosts(session, newer)
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))

    new_views: list[FindingView] = []
    resolved_views: list[FindingView] = []
    changed: list[Changed] = []
    unclear: list[Unclear] = []
    unchanged = unchanged_decided = 0
    rules_differ = False

    if states == ("ready", "ready"):
        old_rows = {
            f.fingerprint: f for f in findings_service.scan_findings(session, older, today=day)
        }
        new_rows = {
            f.fingerprint: f for f in findings_service.scan_findings(session, newer, today=day)
        }
        rules_differ = bool(
            findings_service.evaluation_info(older).get("ruleset")
            != findings_service.evaluation_info(newer).get("ruleset")
        )

        only_new = [f for fp, f in new_rows.items() if fp not in old_rows]
        only_old = [f for fp, f in old_rows.items() if fp not in new_rows]
        both = [fp for fp in new_rows if fp in old_rows]

        decisions = load_decisions(session, assessment.id, set(both), day)
        for fingerprint in both:
            if new_rows[fingerprint].severity == old_rows[fingerprint].severity:
                unchanged += 1
                decision = decisions.get(fingerprint)
                if (
                    decision
                    and decision.status in (ACCEPTED, FALSE_POSITIVE)
                    and not decision.lapsed
                ):
                    unchanged_decided += 1

        changed_rows = [
            new_rows[fp] for fp in both if new_rows[fp].severity != old_rows[fp].severity
        ]
        changed_views = findings_service.describe_all(
            session, changed_rows, assessment.id, today=day
        )
        changed = sorted(
            (
                Changed(view, old_rows[row.fingerprint].severity)
                for row, view in zip(changed_rows, changed_views, strict=True)
            ),
            key=lambda c: (_severity_key(c.finding.severity), c.finding.title, c.finding.subject),
        )

        new_views = findings_service.describe_all(session, only_new, assessment.id, today=day)

        # An older finding is resolved only if what it rested on was asked again and answered.
        evidence = _evidence_of(session, only_old)
        answers = _answers(session, newer)
        older_names = {ref.id: name for name, ref in before.items()}
        old_views = findings_service.describe_all(session, only_old, assessment.id, today=day)
        for row, view in zip(only_old, old_views, strict=True):
            gap = _gap(row, evidence, older_names, answers)
            if gap is None:
                resolved_views.append(view)
            else:
                unclear.append(Unclear(view, gap))
        unclear.sort(
            key=lambda u: (_severity_key(u.finding.severity), u.finding.title, u.finding.subject)
        )

    new_sorted = _ordered(new_views)
    resolved_sorted = _ordered(resolved_views)
    return Comparison(
        older=older,
        newer=newer,
        hosts_added=tuple(after[name] for name in added[:MAX_LISTED]),
        hosts_added_total=len(added),
        hosts_removed=tuple(before[name] for name in removed[:MAX_LISTED]),
        hosts_removed_total=len(removed),
        hosts_kept=len(set(before) & set(after)),
        older_gaps=discovery_gaps(session, older),
        newer_gaps=discovery_gaps(session, newer),
        findings_state=states,
        rules_differ=rules_differ,
        findings_dropped=(
            _count(findings_service.evaluation_info(older).get("dropped")),
            _count(findings_service.evaluation_info(newer).get("dropped")),
        ),
        new=tuple(new_sorted[:MAX_LISTED]),
        new_total=len(new_sorted),
        resolved=tuple(resolved_sorted[:MAX_LISTED]),
        resolved_total=len(resolved_sorted),
        changed=tuple(changed[:MAX_LISTED]),
        changed_total=len(changed),
        unclear=tuple(unclear[:MAX_LISTED]),
        unclear_total=len(unclear),
        unchanged=unchanged,
        unchanged_decided=unchanged_decided,
    )
