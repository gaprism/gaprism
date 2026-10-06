"""Who may open an assessment: shared by the pages and the exports of the assessments blueprint."""

from __future__ import annotations

import uuid
from typing import cast

from flask import abort
from flask_security import current_user

from app.extensions import db
from app.models.assessment import Assessment
from app.models.auth import User
from app.service import assessments as assessment_service


def uuid_or_none(value: str) -> uuid.UUID | None:
    """An identifier out of a request, or ``None`` when it is not one."""
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def current_user_object() -> User:
    """The signed-in user as a model object (not the request-local proxy)."""
    return cast(User, current_user._get_current_object())


def get_accessible(assessment_id: uuid.UUID) -> Assessment:
    """Load an assessment the user may open; otherwise answer 404 (never confirm it exists)."""
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None or not assessment_service.can_access(current_user_object(), assessment):
        abort(404)
    return assessment
