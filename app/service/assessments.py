"""Assessment queries, creation and access rules: the one place that decides who may see what."""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Collection
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit import AUDIT_LOGGER
from app.models.assessment import VISIBILITIES, Assessment
from app.models.auth import User
from app.service.discovery.scope import ScopeValidationError, canonicalise_domain, is_in_scope
from app.service.discovery.service import normalise_name
from app.service.users import ADMIN_ROLE

MAX_LABEL_LENGTH = 255
MAX_MANUAL_HOSTS = 200

audit = logging.getLogger(AUDIT_LOGGER)


class DuplicateAssessmentError(ValueError):
    """The user already has access to an assessment for this domain."""

    def __init__(self, existing: Assessment) -> None:
        super().__init__("An assessment for this domain already exists.")
        self.existing = existing


def is_admin(user: User) -> bool:
    """True for accounts holding the administrator role."""
    return any(role.name == ADMIN_ROLE for role in user.roles)


def can_access(user: User, assessment: Assessment) -> bool:
    """Owners and administrators always; everyone else only for team-shared assessments."""
    return assessment.created_by == user.id or assessment.visibility == "team" or is_admin(user)


def can_manage(user: User, assessment: Assessment) -> bool:
    """Who decides how widely an assessment is shared: its owner and the administrators. Everyone
    who can open a team assessment may work on it (scan, decide, add hosts), but not hide it from
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
    """Share an assessment with the whole team, or make it private again. The caller checks that
    ``user`` may manage it and commits.

    Raises ``DuplicateAssessmentError`` when another assessment of the domain is already shared:
    the team would then have two.
    """
    if visibility not in VISIBILITIES:
        raise ValueError(f"Unknown visibility: {visibility!r}")
    if visibility == assessment.visibility:
        return
    if visibility == "team":
        existing = session.scalar(
            select(Assessment)
            .where(
                Assessment.domain == assessment.domain,
                Assessment.visibility == "team",
                Assessment.id != assessment.id,
            )
            .limit(1)
        )
        if existing is not None:
            raise DuplicateAssessmentError(existing)
    assessment.visibility = visibility
    session.flush()
    audit.info(
        "assessment visibility: assessment=%s visibility=%s by=%s",
        assessment.id,
        visibility,
        user.id,
    )


def list_visible(session: Session, user: User) -> list[Assessment]:
    """Assessments the user may open, newest first."""
    stmt = select(Assessment).order_by(Assessment.created_at.desc())
    if not is_admin(user):
        stmt = stmt.where(or_(Assessment.created_by == user.id, Assessment.visibility == "team"))
    return list(session.scalars(stmt))


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
        raise ScopeValidationError("This domain is on the blocklist and cannot be assessed.")
    if visibility not in VISIBILITIES:
        raise ValueError(f"Unknown visibility: {visibility!r}")
    clean_label = (label or "").strip()
    if len(clean_label) > MAX_LABEL_LENGTH:
        raise ValueError(f"The label may not exceed {MAX_LABEL_LENGTH} characters.")

    for existing in list_visible(session, user):
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
    return ManualHostsResult(tuple(added), tuple(present), tuple(rejected))


def remove_manual_host(session: Session, assessment: Assessment, hostname: str) -> bool:
    """Remove a manually added hostname; False if it was not in the list."""
    remaining = [host for host in assessment.manual_hosts if host != hostname]
    if len(remaining) == len(assessment.manual_hosts):
        return False
    assessment.manual_hosts = remaining
    session.flush()
    return True
