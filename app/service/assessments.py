"""Assessment queries, creation and access rules: the one place that decides who may see what."""

from __future__ import annotations

from collections.abc import Collection

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.assessment import VISIBILITIES, Assessment
from app.models.auth import User
from app.service.discovery.scope import ScopeValidationError, canonicalise_domain, is_in_scope
from app.service.users import ADMIN_ROLE

MAX_LABEL_LENGTH = 255


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
