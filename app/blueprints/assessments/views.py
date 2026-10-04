"""Routes for assessments. Thin: parse the request, call a service, render."""

from __future__ import annotations

import uuid
from typing import Any, cast

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_security import current_user, login_required
from werkzeug.wrappers import Response

from app.blueprints.assessments import assessments_bp
from app.blueprints.assessments.forms import NewAssessmentForm
from app.extensions import db
from app.i18n import gettext as _
from app.models.assessment import Assessment
from app.models.auth import User
from app.service import assessments as assessment_service
from app.service import scans as scan_service
from app.service.discovery.scope import ScopeValidationError

MAX_HOSTNAMES_INPUT = 20_000  # characters accepted in the "add hosts" box


def _current_user() -> User:
    return cast(User, current_user._get_current_object())


def _get_accessible(assessment_id: uuid.UUID) -> Assessment:
    """Load an assessment the user may open; otherwise answer 404 (never confirm it exists)."""
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None or not assessment_service.can_access(_current_user(), assessment):
        abort(404)
    return assessment


def _panel_context(assessment: Assessment) -> dict[str, Any]:
    """What the scan panel needs: the latest scan, its hosts (filtered, paged) and notes."""
    query = request.args.get("q", "")[:100]
    page = max(1, request.args.get("page", 1, type=int) or 1)
    scan = scan_service.get_latest_scan(db.session(), assessment.id)
    overview = (
        scan_service.scan_overview(db.session(), scan, query=query, page=page) if scan else None
    )
    return {"assessment": assessment, "overview": overview, "q": query, "page": page}


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
    """Show one assessment with its latest scan."""
    return render_template(
        "assessments/detail.html", **_panel_context(_get_accessible(assessment_id))
    )


@assessments_bp.get("/<uuid:assessment_id>/scan-panel")
@login_required
def scan_panel(assessment_id: uuid.UUID) -> str:
    """The scan panel alone; the page polls it while a scan is queued or running."""
    return render_template(
        "assessments/_scan_panel.html", **_panel_context(_get_accessible(assessment_id))
    )


@assessments_bp.post("/<uuid:assessment_id>/scans")
@login_required
def start_scan(assessment_id: uuid.UUID) -> Response:
    """Queue a new scan (a worker picks it up)."""
    assessment = _get_accessible(assessment_id)
    try:
        scan_service.start_scan(db.session(), assessment, _current_user(), current_app.config)
    except scan_service.ScanInProgressError:
        db.session.rollback()
        flash(_("A scan is already queued or running for this assessment."), "warning")
    else:
        db.session.commit()
        flash(_("Scan queued."), "info")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


@assessments_bp.post("/<uuid:assessment_id>/scans/cancel")
@login_required
def cancel_scan(assessment_id: uuid.UUID) -> Response:
    """Stop the running scan: queued checks are skipped, running ones finish."""
    assessment = _get_accessible(assessment_id)
    if scan_service.cancel_active_scan(db.session(), assessment.id):
        db.session.commit()
        flash(_("Scan cancelled. Checks that were already running will finish."), "info")
    else:
        db.session.rollback()
        flash(_("There is no running scan to cancel."), "warning")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


@assessments_bp.post("/<uuid:assessment_id>/hosts")
@login_required
def add_hosts(assessment_id: uuid.UUID) -> Response:
    """Add hostnames by hand; they join every later scan."""
    assessment = _get_accessible(assessment_id)
    raw = request.form.get("hostnames", "")[:MAX_HOSTNAMES_INPUT]
    result = assessment_service.add_manual_hosts(db.session(), assessment, raw)
    db.session.commit()
    if result.added:
        flash(
            _(
                "%(count)s host(s) added. They are included in the next scan.",
                count=len(result.added),
            ),
            "info",
        )
    if result.already_present:
        flash(_("Already included: %(hosts)s", hosts=", ".join(result.already_present)), "info")
    for entered, reason in result.rejected:
        flash(_("Not added: %(host)s (%(reason)s)", host=entered[:80], reason=reason), "warning")
    if not (result.added or result.already_present or result.rejected):
        flash(_("Enter at least one hostname."), "warning")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


@assessments_bp.post("/<uuid:assessment_id>/hosts/remove")
@login_required
def remove_host(assessment_id: uuid.UUID) -> Response:
    """Remove a manually added hostname."""
    assessment = _get_accessible(assessment_id)
    hostname = request.form.get("hostname", "")
    if assessment_service.remove_manual_host(db.session(), assessment, hostname):
        db.session.commit()
        flash(_("Removed %(host)s.", host=hostname), "info")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))
