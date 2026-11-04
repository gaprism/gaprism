"""Assessment queries, creation and access rules: the one place that decides who may see what."""

from __future__ import annotations

import re
import uuid
from collections.abc import Collection
from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingDisposition, Host, Scan
from app.models.assessment import VISIBILITIES, Assessment
from app.models.auth import User
from app.models.base import utc_now
from app.models.scan import ACTIVE_SCAN_STATUSES
from app.service import audit as audit_service
from app.service.discovery.scope import ScopeValidationError, canonicalise_domain, is_in_scope
from app.service.discovery.service import normalise_name
from app.service.users import ADMIN_ROLE

MAX_LABEL_LENGTH = 255
MAX_MANUAL_HOSTS = 200


class DuplicateAssessmentError(ValueError):
    """The user already has access to an assessment for this domain."""

    def __init__(self, existing: Assessment) -> None:
        super().__init__("An assessment for this domain already exists.")
        self.existing = existing


class AssessmentBusyError(Exception):
    """A scan is queued or running: cancel it, or wait for it, before archiving or deleting."""


class AssessmentArchivedError(Exception):
    """The assessment is archived and read-only: restore it to change it."""


def is_admin(user: User) -> bool:
    """True for accounts holding the administrator role."""
    return any(role.name == ADMIN_ROLE for role in user.roles)


def can_access(user: User, assessment: Assessment) -> bool:
    """Owners and administrators always; everyone else only for shared assessments."""
    return assessment.created_by == user.id or assessment.visibility == "shared" or is_admin(user)


def can_manage(user: User, assessment: Assessment) -> bool:
    """Who decides how widely an assessment is shared: its owner and the administrators. Everyone
    who can open a shared assessment may work on it (scan, decide, add hosts), but not hide it from
    the others."""
    return assessment.created_by == user.id or is_admin(user)


def owner_emails(session: Session, assessments: Collection[Assessment]) -> dict[uuid.UUID, str]:
    """The e-mail address of the owner of each assessment, by assessment id (one query)."""
    owners = {assessment.created_by for assessment in assessments}
    if not owners:
        return {}
    emails = dict(session.execute(select(User.id, User.email).where(User.id.in_(owners))).all())
    return {a.id: emails.get(a.created_by, "") for a in assessments}


def set_visibility(session: Session, assessment: Assessment, visibility: str, user: User) -> None:
    """Share an assessment with every signed-in user, or make it private again. The caller checks
    that ``user`` may manage it and commits.

    Raises ``DuplicateAssessmentError`` when another assessment of the domain is already shared:
    everyone would then have two.
    """
    if visibility not in VISIBILITIES:
        raise ValueError(f"Unknown visibility: {visibility!r}")
    if visibility == assessment.visibility:
        return
    if visibility == "shared":
        existing = session.scalar(
            select(Assessment)
            .where(
                Assessment.domain == assessment.domain,
                Assessment.visibility == "shared",
                Assessment.id != assessment.id,
            )
            .limit(1)
        )
        if existing is not None:
            raise DuplicateAssessmentError(existing)
    assessment.visibility = visibility
    session.flush()
    audit_service.record(
        session,
        "assessment.shared" if visibility == "shared" else "assessment.unshared",
        actor=user,
        assessment=assessment,
    )


def list_visible(session: Session, user: User, archived: bool | None = False) -> list[Assessment]:
    """Assessments the user may open, newest first: the live ones by default, only the archived
    ones with ``archived=True``, all of them with ``None``."""
    stmt = select(Assessment).order_by(Assessment.created_at.desc())
    if not is_admin(user):
        stmt = stmt.where(or_(Assessment.created_by == user.id, Assessment.visibility == "shared"))
    if archived is True:
        stmt = stmt.where(Assessment.archived_at.is_not(None))
    elif archived is False:
        stmt = stmt.where(Assessment.archived_at.is_(None))
    return list(session.scalars(stmt))


def _locked(session: Session, assessment: Assessment) -> Assessment:
    """The assessment's row, locked until the transaction ends. Archiving and deleting then queue
    up behind a scan that is being started, and a scan that is started during one of them waits."""
    row: Assessment | None = session.scalar(
        select(Assessment).where(Assessment.id == assessment.id).with_for_update()
    )
    if row is None:
        raise LookupError("The assessment no longer exists.")
    return row


def _scan_active(session: Session, assessment: Assessment) -> bool:
    return (
        session.scalar(
            select(Scan.id)
            .where(Scan.assessment_id == assessment.id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
            .limit(1)
        )
        is not None
    )


def archive(session: Session, assessment: Assessment, user: User) -> bool:
    """Hide an assessment from the default list and make it read-only; scans, hosts and decisions
    stay. ``False`` if it was archived already. Raises ``AssessmentBusyError`` while a scan is
    queued or running. The caller checks that ``user`` may manage it and commits."""
    row = _locked(session, assessment)
    if row.archived_at is not None:
        return False
    if _scan_active(session, row):
        raise AssessmentBusyError
    row.archived_at = utc_now()
    session.flush()
    audit_service.record(session, "assessment.archived", actor=user, assessment=row)
    return True


def unarchive(session: Session, assessment: Assessment, user: User) -> bool:
    """Bring an archived assessment back to the list. ``False`` if it was not archived. The caller
    checks that ``user`` may manage it and commits."""
    row = _locked(session, assessment)
    if row.archived_at is None:
        return False
    row.archived_at = None
    session.flush()
    audit_service.record(session, "assessment.unarchived", actor=user, assessment=row)
    return True


@dataclass(frozen=True)
class Contents:
    """What an assessment holds: what deleting it takes with it."""

    scans: int
    hosts: int
    findings: int
    decisions: int


def contents(session: Session, assessment: Assessment) -> Contents:
    """Count what belongs to the assessment (for the confirmation page and the audit entry)."""

    def count(*statement: object) -> int:
        return int(session.scalar(*statement) or 0)  # type: ignore[call-overload]

    return Contents(
        scans=count(
            select(func.count()).select_from(Scan).where(Scan.assessment_id == assessment.id)
        ),
        hosts=count(
            select(func.count())
            .select_from(Host)
            .join(Scan, Scan.id == Host.scan_id)
            .where(Scan.assessment_id == assessment.id)
        ),
        findings=count(
            select(func.count())
            .select_from(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Scan.assessment_id == assessment.id)
        ),
        decisions=count(
            select(func.count())
            .select_from(FindingDisposition)
            .where(FindingDisposition.assessment_id == assessment.id)
        ),
    )


def delete_assessment(session: Session, assessment: Assessment, user: User) -> Contents:
    """Delete an assessment with its scans, hosts, check results, findings and decisions (the
    foreign keys cascade). Raises ``AssessmentBusyError`` while a scan is queued or running.

    The audit entry is written first, with the domain and what went with it; its link to the
    assessment is cleared by the delete and the entry stays. The caller checks that ``user`` may
    manage it, and commits."""
    row = _locked(session, assessment)
    if _scan_active(session, row):
        raise AssessmentBusyError
    taken = contents(session, row)
    audit_service.record(
        session,
        "assessment.deleted",
        actor=user,
        assessment=row,
        subject=str(row.id),
        details={
            "scans": taken.scans,
            "hosts": taken.hosts,
            "findings": taken.findings,
            "decisions": taken.decisions,
            "visibility": row.visibility,
            "archived": row.archived_at is not None,
        },
    )
    session.delete(row)
    session.flush()
    return taken


def create_assessment(
    session: Session,
    user: User,
    raw_domain: str,
    label: str | None = None,
    visibility: str = "private",
    blocked_domains: Collection[str] = (),
) -> Assessment:
    """Validate the entered domain and create an assessment owned by ``user``.

    Raises ``ScopeValidationError`` for anything that is not a plain, assessable domain name
    (URLs, IP addresses, wildcards, public suffixes, blocked domains) and
    ``DuplicateAssessmentError`` when the user can already open an assessment for it.
    The caller commits.
    """
    scope = canonicalise_domain(raw_domain)
    if any(is_in_scope(scope.canonical, blocked) for blocked in blocked_domains):
        raise ScopeValidationError(
            "This installation does not assess this domain: it is on the list of blocked domains. "
            "Ask an administrator if that is a mistake."
        )
    if visibility not in VISIBILITIES:
        raise ValueError(f"Unknown visibility: {visibility!r}")
    clean_label = (label or "").strip()
    if len(clean_label) > MAX_LABEL_LENGTH:
        raise ValueError(f"The label has more than {MAX_LABEL_LENGTH} characters. Shorten it.")

    for existing in list_visible(session, user, archived=None):  # an archived one keeps its domain
        if existing.domain == scope.canonical:
            raise DuplicateAssessmentError(existing)

    assessment = Assessment(
        domain=scope.canonical,
        domain_display=scope.unicode,
        label=clean_label or None,
        visibility=visibility,
        created_by=user.id,
    )
    session.add(assessment)
    session.flush()
    audit_service.record(
        session,
        "assessment.created",
        actor=user,
        assessment=assessment,
        details={"visibility": visibility},
    )
    return assessment


@dataclass(frozen=True)
class ManualHostsResult:
    """What happened to the hostnames an analyst entered."""

    added: tuple[str, ...]
    already_present: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]  # (what was entered, why it was refused)


def add_manual_hosts(session: Session, assessment: Assessment, raw: str) -> ManualHostsResult:
    """Add hostnames (separated by whitespace, commas or semicolons) to the assessment.

    Only concrete hostnames inside the assessed domain are accepted. They join every later scan
    and get the same checks as discovered hosts. The caller commits.
    """
    existing = list(assessment.manual_hosts)
    added: list[str] = []
    present: list[str] = []
    rejected: list[tuple[str, str]] = []
    for token in re.split(r"[\s,;]+", raw.strip()):
        if not token:
            continue
        parsed = normalise_name(token)
        if parsed is None:
            rejected.append((token, "not a valid hostname"))
            continue
        hostname, wildcard = parsed
        if wildcard:
            rejected.append((token, "wildcards are patterns, not hosts"))
        elif not is_in_scope(hostname, assessment.domain):
            rejected.append((token, f"outside {assessment.domain_display}"))
        elif hostname == assessment.domain or hostname in existing or hostname in added:
            present.append(hostname)  # the apex is always reviewed
        elif len(existing) + len(added) >= MAX_MANUAL_HOSTS:
            rejected.append((token, f"limit of {MAX_MANUAL_HOSTS} manual hosts reached"))
        else:
            added.append(hostname)
    if added:
        assessment.manual_hosts = [*existing, *added]
        session.flush()
        audit_service.record(
            session,
            "hosts.added",
            assessment=assessment,
            details={"count": len(added), "hosts": added},
        )
    return ManualHostsResult(tuple(added), tuple(present), tuple(rejected))


def remove_manual_host(session: Session, assessment: Assessment, hostname: str) -> bool:
    """Remove a manually added hostname; False if it was not in the list."""
    remaining = [host for host in assessment.manual_hosts if host != hostname]
    if len(remaining) == len(assessment.manual_hosts):
        return False
    assessment.manual_hosts = remaining
    session.flush()
    audit_service.record(
        session, "hosts.removed", assessment=assessment, details={"host": hostname}
    )
    return True
