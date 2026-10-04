"""Routes for assessments. Thin: parse the request, call a service, render."""

from __future__ import annotations

from typing import cast

from flask import render_template
from flask_security import current_user, login_required

from app.blueprints.assessments import assessments_bp
from app.extensions import db
from app.models.auth import User
from app.service import assessments as assessment_service


@assessments_bp.get("/")
@login_required
def index() -> str:
    """List the assessments the signed-in user may open."""
    user = cast(User, current_user._get_current_object())
    return render_template(
        "assessments/index.html",
        assessments=assessment_service.list_visible(db.session(), user),
    )
