"""The scans of an assessment over time, and the comparison of two of them. Thin routes: check
access, ask the service, render. Everything is read-only."""

from __future__ import annotations

import uuid

from flask import abort, flash, redirect, render_template, request, url_for
from flask_security import login_required
from werkzeug.wrappers import Response

from app.blueprints.assessments import assessments_bp
from app.blueprints.assessments.access import get_accessible, uuid_or_none
from app.extensions import db
from app.i18n import gettext as _
from app.service import history as history_service


@assessments_bp.get("/<uuid:assessment_id>/scans")
@login_required
def scan_history(assessment_id: uuid.UUID) -> str:
    """Every scan of the assessment, newest first, with what it found and where its report is."""
    assessment = get_accessible(assessment_id)
    session = db.session()
    finished = history_service.finished_scans(session, assessment.id)
    return render_template(
        "assessments/history.html",
        assessment=assessment,
        rows=history_service.list_scans(session, assessment.id),
        finished=finished,
        default=history_service.default_pair(finished),
    )


@assessments_bp.get("/<uuid:assessment_id>/compare")
@login_required
def compare_scans(assessment_id: uuid.UUID) -> str | Response:
    """What changed between two finished scans: the two newest that ran to the end, or the two the
    query names (``from`` and ``to``, in either order)."""
    assessment = get_accessible(assessment_id)
    session = db.session()
    finished = history_service.finished_scans(session, assessment.id)

    if "from" in request.args or "to" in request.args:
        chosen = [
            history_service.get_scan(session, assessment.id, scan_id)
            if (scan_id := uuid_or_none(request.args.get(name, ""))) is not None
            else None
            for name in ("from", "to")
        ]
        first, second = chosen
        if first is None or second is None or not (first.is_terminal and second.is_terminal):
            abort(404)  # a scan of another assessment, or one that has not ended: never confirmed
        if first.id == second.id:
            flash(_("Choose two different scans to compare."), "warning")
            return redirect(url_for("assessments.scan_history", assessment_id=assessment.id))
        older, newer = history_service.in_order(first, second)
    else:
        pair = history_service.default_pair(finished)
        if pair is None:
            return render_template(
                "assessments/compare.html",
                assessment=assessment,
                finished=finished,
                comparison=None,
            )
        older, newer = pair

    return render_template(
        "assessments/compare.html",
        assessment=assessment,
        finished=finished,
        comparison=history_service.compare(session, assessment, older, newer),
    )
