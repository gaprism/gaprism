"""Routes for assessments. Thin: parse the request, call a service, render."""

from __future__ import annotations

import uuid
from typing import cast

from flask import abort, current_app, flash, redirect, render_template, url_for
from flask_security import current_user, login_required
from werkzeug.wrappers import Response

from app.blueprints.assessments import assessments_bp
from app.blueprints.assessments.forms import NewAssessmentForm
from app.extensions import db
from app.i18n import gettext as _
from app.models.assessment import Assessment
from app.models.auth import User
from app.service import assessments as assessment_service
from app.service.discovery.scope import ScopeValidationError


def _current_user() -> User:
    return cast(User, current_user._get_current_object())


def _get_accessible(assessment_id: uuid.UUID) -> Assessment:
    """Load an assessment the user may open; otherwise answer 404 (never confirm it exists)."""
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None or not assessment_service.can_access(_current_user(), assessment):
        abort(404)
    return assessment


@assessments_bp.get("/")
@login_required
def index() -> str:
    """List the assessments the signed-in user may open."""
    return render_template(
        "assessments/index.html",
        assessments=assessment_service.list_visible(db.session(), _current_user()),
    )


@assessments_bp.route("/new", methods=["GET", "POST"])
@login_required
def new() -> str | Response:
    """Create an assessment from a domain name."""
    form = NewAssessmentForm()
    existing: Assessment | None = None
    if form.validate_on_submit():
        try:
            assessment = assessment_service.create_assessment(
                db.session(),
                _current_user(),
                form.domain.data or "",
                label=form.label.data,
                visibility=form.visibility.data or "private",
                blocked_domains=current_app.config["BLOCKED_DOMAINS"],
            )
        except ScopeValidationError as exc:
            form.domain.errors = [*form.domain.errors, str(exc)]
        except assessment_service.DuplicateAssessmentError as exc:
            existing = exc.existing
            form.domain.errors = [*form.domain.errors, _("This domain is already being assessed.")]
        except ValueError as exc:
            form.label.errors = [*form.label.errors, str(exc)]
        else:
            db.session.commit()
            flash(_("Assessment created."), "info")
            return redirect(url_for("assessments.detail", assessment_id=assessment.id))
    return render_template("assessments/new.html", form=form, existing=existing)


@assessments_bp.get("/<uuid:assessment_id>")
@login_required
def detail(assessment_id: uuid.UUID) -> str:
    """Show one assessment."""
    return render_template("assessments/detail.html", assessment=_get_accessible(assessment_id))
