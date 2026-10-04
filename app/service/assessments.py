"""Assessment queries and access rules: the one place that decides who may see what."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import User
from app.service.users import ADMIN_ROLE


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
