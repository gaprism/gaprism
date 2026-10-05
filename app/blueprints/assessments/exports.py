"""Exports of the latest finished scan: the printable report, JSON, and two CSV files.

Thin, like the other routes: check access, find the scan, ask the services for the data, send it.
The files carry findings about a vendor, so they follow the access rules of the assessment and are
never cached (the application sets ``Cache-Control: no-store`` on every response)."""

from __future__ import annotations

import logging
import uuid

from flask import current_app, flash, redirect, render_template, url_for
from flask_security import login_required
from werkzeug.wrappers import Response

from app.audit import AUDIT_LOGGER
from app.blueprints.assessments import assessments_bp
from app.blueprints.assessments.access import current_user_object, get_accessible
from app.extensions import db
from app.i18n import gettext as _
from app.models.assessment import Assessment
from app.service import export as export_service
from app.service import report as report_service
from app.service import scans as scan_service

audit = logging.getLogger(AUDIT_LOGGER)


def _export_data(assessment: Assessment, kind: str) -> export_service.ExportData | None:
    """The export of the latest scan, or ``None`` (with a message) when there is nothing to export:
    no scan yet, or one that still runs."""
    scan = scan_service.get_latest_scan(db.session(), assessment.id)
    if scan is None or not scan.is_terminal:
        flash(_("Export a scan once it has finished."), "warning")
        return None
    data = export_service.build_export(db.session(), assessment, scan, current_app.config)
    audit.info(
        "export: kind=%s assessment=%s scan=%s by=%s",
        kind,
        assessment.id,
        scan.id,
        current_user_object().id,
    )
    return data


def _back(assessment: Assessment) -> Response:
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


def _download(body: str, content_type: str, filename: str) -> Response:
    response = Response(body, content_type=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@assessments_bp.get("/<uuid:assessment_id>/report")
@login_required
def report(assessment_id: uuid.UUID) -> str | Response:
    """The report of the latest scan, laid out to be printed (or saved as PDF by the browser)."""
    assessment = get_accessible(assessment_id)
    data = _export_data(assessment, "report")
    if data is None:
        return _back(assessment)
    return render_template(
        "assessments/report.html", assessment=assessment, report=report_service.build_report(data)
    )


@assessments_bp.get("/<uuid:assessment_id>/export/scan.json")
@login_required
def export_json(assessment_id: uuid.UUID) -> Response:
    """Everything the scan found, as JSON (see docs/export-format.md)."""
    assessment = get_accessible(assessment_id)
    data = _export_data(assessment, "json")
    if data is None:
        return _back(assessment)
    return _download(
        export_service.to_json(data),
        "application/json; charset=utf-8",
        export_service.export_filename(data, "scan", "json"),
    )


@assessments_bp.get("/<uuid:assessment_id>/export/hosts.csv")
@login_required
def export_hosts_csv(assessment_id: uuid.UUID) -> Response:
    """One row per host."""
    assessment = get_accessible(assessment_id)
    data = _export_data(assessment, "hosts_csv")
    if data is None:
        return _back(assessment)
    return _download(
        export_service.hosts_csv(data),
        "text/csv; charset=utf-8",
        export_service.export_filename(data, "hosts", "csv"),
    )


@assessments_bp.get("/<uuid:assessment_id>/export/findings.csv")
@login_required
def export_findings_csv(assessment_id: uuid.UUID) -> Response:
    """One row per finding, with what the team decided about it."""
    assessment = get_accessible(assessment_id)
    data = _export_data(assessment, "findings_csv")
    if data is None:
        return _back(assessment)
    return _download(
        export_service.findings_csv(data),
        "text/csv; charset=utf-8",
        export_service.export_filename(data, "findings", "csv"),
    )
