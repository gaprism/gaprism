"""Routes for assessments. Thin: parse the request, call a service, render."""

from __future__ import annotations

import math
import re
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_security import login_required
from werkzeug.wrappers import Response

from app.blueprints.assessments import assessments_bp
from app.blueprints.assessments.access import current_user_object as _current_user
from app.blueprints.assessments.access import get_accessible as _get_accessible
from app.blueprints.assessments.access import uuid_or_none as _uuid_or_none
from app.blueprints.assessments.forms import NewAssessmentForm
from app.extensions import db
from app.i18n import gettext as _
from app.i18n import ngettext
from app.models.assessment import VISIBILITIES, Assessment
from app.models.finding import Finding
from app.service import assessments as assessment_service
from app.service import audit as audit_service
from app.service import decisions as decision_service
from app.service import disclosure as disclosure_service
from app.service import exploits as exploit_service
from app.service import findings as findings_service
from app.service import host_view as host_view_service
from app.service import scans as scan_service
from app.service.discovery.scope import ScopeValidationError

MAX_HOSTNAMES_INPUT = 20_000  # characters accepted in the "add hosts" box
MAX_QUERY_INPUT = 500  # characters of the findings page's own query that a decision form returns
RULE_ID = re.compile(r"[A-Za-z0-9_]{1,64}")

# Translated labels for reason codes, available in every template.
assessments_bp.add_app_template_global(host_view_service.reason_label, "reason_label")
assessments_bp.add_app_template_global(host_view_service.tls_failure_label, "tls_failure_label")
assessments_bp.add_app_template_global(host_view_service.problem_label, "problem_label")
assessments_bp.add_app_template_global(findings_service.severity_label, "severity_label")
assessments_bp.add_app_template_global(findings_service.severity_tone, "severity_tone")
assessments_bp.add_app_template_global(findings_service.confidence_label, "confidence_label")
assessments_bp.add_app_template_global(findings_service.attribution_label, "attribution_label")
assessments_bp.add_app_template_global(findings_service.status_label, "status_label")
assessments_bp.add_app_template_global(host_view_service.check_title, "check_title")
assessments_bp.add_app_template_global(host_view_service.category_label, "category_label")
assessments_bp.add_app_template_global(host_view_service.ede_label, "ede_label")
assessments_bp.add_app_template_global(host_view_service.blocklist_name, "blocklist_name")
assessments_bp.add_app_template_global(host_view_service.blocklist_names, "blocklist_names")
assessments_bp.add_app_template_global(host_view_service.blocklist_about, "blocklist_about")
assessments_bp.add_app_template_global(decision_service.review_window, "review_window")
assessments_bp.add_app_template_global(exploit_service.epss_percent, "epss_percent")
assessments_bp.add_app_template_global(exploit_service.sources_used, "exploit_sources")


def _panel_context(assessment: Assessment) -> dict[str, Any]:
    """What the scan panel needs: the latest scan, its hosts (filtered, paged) and notes."""
    query = request.args.get("q", "")[:100]
    page = max(1, request.args.get("page", 1, type=int) or 1)
    state = request.args.get("state", "all")
    if state not in scan_service.HOST_STATES:
        state = "all"
    scan = scan_service.get_latest_scan(db.session(), assessment.id)
    overview = (
        scan_service.scan_overview(
            db.session(), scan, query=query, page=page, state=state, config=current_app.config
        )
        if scan
        else None
    )
    user = _current_user()
    return {
        "assessment": assessment,
        "overview": overview,
        "q": query,
        "page": page,
        "state": state,
        "owner_email": assessment_service.owner_emails(db.session(), [assessment])[assessment.id],
        "can_manage": assessment_service.can_manage(user, assessment),
    }


@assessments_bp.get("/")
@login_required
def index() -> str:
    """List the assessments the signed-in user may open: the live ones, or the archived ones."""
    everything = assessment_service.list_visible(db.session(), _current_user(), archived=None)
    live = [item for item in everything if item.archived_at is None]
    archived = sorted(
        (item for item in everything if item.archived_at is not None),
        key=lambda item: item.archived_at or item.created_at,
        reverse=True,
    )
    viewing_archive = request.args.get("view") == "archived"
    shown = archived if viewing_archive else live
    return render_template(
        "assessments/index.html",
        assessments=shown,
        owners=assessment_service.owner_emails(db.session(), shown),
        viewing_archive=viewing_archive,
        counts={"live": len(live), "archived": len(archived)},
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
    return render_template(
        "assessments/new.html",
        form=form,
        existing=existing,
        disclosure=disclosure_service.describe(current_app.config),
    )


@assessments_bp.get("/<uuid:assessment_id>")
@login_required
def detail(assessment_id: uuid.UUID) -> str:
    """Show one assessment with its latest scan."""
    return render_template(
        "assessments/detail.html", **_panel_context(_get_accessible(assessment_id))
    )


@assessments_bp.post("/<uuid:assessment_id>/visibility")
@login_required
def set_visibility(assessment_id: uuid.UUID) -> Response:
    """Share the assessment with the whole team, or make it private again (owner and
    administrators only)."""
    assessment = _get_accessible(assessment_id)
    user = _current_user()
    if not assessment_service.can_manage(user, assessment):
        abort(403)  # a colleague may work on a shared assessment, not hide it from the others
    wanted = request.form.get("visibility", "")
    if wanted not in VISIBILITIES:
        abort(400)
    try:
        assessment_service.set_visibility(db.session(), assessment, wanted, user)
    except assessment_service.DuplicateAssessmentError:
        db.session.rollback()
        flash(
            _(
                "The team already has a shared assessment for %(domain)s, so this one cannot be "
                "shared as well.",
                domain=assessment.domain_display,
            ),
            "warning",
        )
    else:
        db.session.commit()
        flash(
            _("Shared with the team: every signed-in user can open it.")
            if wanted == "team"
            else _("Now private: only the owner and the administrators can open it."),
            "info",
        )
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


def _archived_refusal(assessment: Assessment) -> Response | None:
    """A redirect with a message when the assessment is archived (read-only); else ``None``."""
    if assessment.archived_at is None:
        return None
    flash(_("This assessment is archived and read-only. Restore it to change it."), "warning")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


def _manageable(assessment_id: uuid.UUID) -> Assessment:
    """An assessment the signed-in user may archive or delete (the owner or an administrator);
    a colleague who can only open it gets 403, a stranger 404."""
    assessment = _get_accessible(assessment_id)
    if not assessment_service.can_manage(_current_user(), assessment):
        abort(403)
    return assessment


@assessments_bp.post("/<uuid:assessment_id>/archive")
@login_required
def archive_assessment(assessment_id: uuid.UUID) -> Response:
    """Hide the assessment from the list and make it read-only (owner and administrators)."""
    assessment = _manageable(assessment_id)
    try:
        archived = assessment_service.archive(db.session(), assessment, _current_user())
    except assessment_service.AssessmentBusyError:
        db.session.rollback()
        flash(
            _(
                "A scan is queued or running for this assessment. "
                "Cancel it, or wait for it, before archiving it."
            ),
            "warning",
        )
        return redirect(url_for("assessments.detail", assessment_id=assessment.id))
    db.session.commit()
    if archived:
        flash(
            _(
                "Archived. It is hidden from the list: "
                "the Archived tab has it, and you can restore it."
            ),
            "info",
        )
    return redirect(url_for("assessments.index"))


@assessments_bp.post("/<uuid:assessment_id>/unarchive")
@login_required
def unarchive_assessment(assessment_id: uuid.UUID) -> Response:
    """Bring an archived assessment back to the list (owner and administrators)."""
    assessment = _manageable(assessment_id)
    if assessment_service.unarchive(db.session(), assessment, _current_user()):
        db.session.commit()
        flash(_("Restored from the archive."), "info")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))


@assessments_bp.route("/<uuid:assessment_id>/delete", methods=["GET", "POST"])
@login_required
def delete_assessment(assessment_id: uuid.UUID) -> str | Response:
    """Delete the assessment for good, after the person typed its domain (owner and
    administrators). The page says what goes with it."""
    assessment = _manageable(assessment_id)
    error: str | None = None
    if request.method == "POST":
        typed = request.form.get("confirm", "")[:300].strip().lower()
        if typed not in {assessment.domain, assessment.domain_display.lower()}:
            error = _("That is not the domain, so nothing was deleted.")
        else:
            domain = assessment.domain_display
            try:
                assessment_service.delete_assessment(db.session(), assessment, _current_user())
            except assessment_service.AssessmentBusyError:
                db.session.rollback()
                flash(
                    _(
                        "A scan is queued or running for this assessment. "
                        "Cancel it, or wait for it, before deleting it."
                    ),
                    "warning",
                )
                return redirect(url_for("assessments.detail", assessment_id=assessment.id))
            db.session.commit()
            flash(_("Deleted %(domain)s.", domain=domain), "info")
            return redirect(url_for("assessments.index"))
    return render_template(
        "assessments/delete.html",
        assessment=assessment,
        contents=assessment_service.contents(db.session(), assessment),
        scan_active=scan_service.get_active_scan(db.session(), assessment.id) is not None,
        error=error,
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
    except assessment_service.AssessmentArchivedError:
        db.session.rollback()
        flash(_("This assessment is archived and read-only. Restore it to change it."), "warning")
    except scan_service.ScanInProgressError:
        db.session.rollback()
        flash(_("A scan is already queued or running for this assessment."), "warning")
    except scan_service.ScanRateLimitError as exc:
        db.session.rollback()
        audit_service.record(
            db.session(), "scan.refused", assessment=assessment, details={"limit": exc.limit}
        )
        db.session.commit()  # the refusal itself is worth keeping
        flash(
            ngettext(
                "You have started the most scans allowed in an hour (%(count)s). "
                "The next one can start in about %(num)s minute.",
                "You have started the most scans allowed in an hour (%(count)s). "
                "The next one can start in about %(num)s minutes.",
                max(1, math.ceil(exc.retry_after.total_seconds() / 60)),
                count=exc.limit,
            ),
            "warning",
        )
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


@assessments_bp.get("/<uuid:assessment_id>/hosts/<uuid:host_id>")
@login_required
def host_detail(assessment_id: uuid.UUID, host_id: uuid.UUID) -> str:
    """Everything collected about one host, check by check."""
    assessment = _get_accessible(assessment_id)
    detail = host_view_service.get_host_detail(db.session(), host_id)
    if detail is None or detail.assessment.id != assessment.id:
        abort(404)  # also for a host of someone else's assessment: never confirm it exists
    return render_template(
        "assessments/host.html",
        assessment=assessment,
        detail=detail,
        findings=findings_service.host_findings(db.session(), detail.scan, host_id),
    )


def _findings_filters(values: Mapping[str, str]) -> dict[str, Any]:
    """The filters of the findings page out of a query (the page's own, or the one a decision form
    sends back), each checked: nothing else is passed on."""
    filters: dict[str, Any] = {}
    if values.get("severity", "") in findings_service.SEVERITIES:
        filters["severity"] = values["severity"]
    if RULE_ID.fullmatch(values.get("rule", "")):
        filters["rule"] = values["rule"]
    if values.get("status", "") in decision_service.STATUS_FILTERS:
        filters["status"] = values["status"]
    host = _uuid_or_none(values.get("host", ""))
    if host is not None:
        filters["host"] = host
    if values.get("page", "").isdecimal() and int(values["page"]) > 1:
        filters["page"] = int(values["page"])
    return filters


@assessments_bp.get("/<uuid:assessment_id>/findings")
@login_required
def findings(assessment_id: uuid.UUID) -> str:
    """What the rules found in the latest scan: open findings by default, most serious first."""
    assessment = _get_accessible(assessment_id)
    scan = scan_service.get_latest_scan(db.session(), assessment.id)
    filters = _findings_filters(request.args)
    status = filters.get("status", decision_service.OPEN)
    listing = (
        findings_service.findings_listing(
            db.session(),
            scan,
            severity=filters.get("severity"),
            rule_id=filters.get("rule"),
            host_id=filters.get("host"),
            status=status,
            page=filters.get("page", 1),
        )
        if scan
        else None
    )
    query = request.query_string.decode("ascii", "ignore")[:MAX_QUERY_INPUT]
    return render_template(
        "assessments/findings.html",
        assessment=assessment,
        scan=scan,
        listing=listing,
        filters=filters,
        status=status,
        back={"back": "findings", "q": query},
    )


def _after_decision(assessment: Assessment, finding: Finding) -> str:
    """Where a decision form goes back to: the page it was made on. The target is built from checked
    values, never taken from the request as a URL."""
    anchor = f"finding-{finding.id}"
    if request.form.get("back") == "host":
        host_id = _uuid_or_none(request.form.get("host", ""))
        if host_id is not None:  # the host page answers 404 for a host of another assessment
            return url_for(
                "assessments.host_detail",
                assessment_id=assessment.id,
                host_id=host_id,
                _anchor=anchor,
            )
    raw = parse_qs(request.form.get("q", "")[:MAX_QUERY_INPUT])
    filters = _findings_filters({key: values[0] for key, values in raw.items() if values})
    return url_for("assessments.findings", assessment_id=assessment.id, _anchor=anchor, **filters)


@assessments_bp.post("/<uuid:assessment_id>/findings/<uuid:finding_id>/decision")
@login_required
def decide_finding(assessment_id: uuid.UUID, finding_id: uuid.UUID) -> Response:
    """Accept a finding, mark it as a false positive, or reopen it."""
    assessment = _get_accessible(assessment_id)
    if (refusal := _archived_refusal(assessment)) is not None:
        return refusal
    finding = decision_service.get_finding(db.session(), assessment.id, finding_id)
    if finding is None:
        abort(404)  # also for a finding of another assessment: never confirm it exists
    form = request.form
    try:
        if form.get("action") == "reopen":
            reopened = decision_service.reopen(
                db.session(), assessment.id, finding, _current_user()
            )
            message = _("Finding reopened.") if reopened else _("This finding was already open.")
        else:
            decision = decision_service.decide(
                db.session(),
                assessment.id,
                finding,
                _current_user(),
                status=form.get("status", ""),
                reason=form.get("reason", "")[: decision_service.MAX_REASON + 1],
                review_by=form.get("review_by", "")[:40],
            )
            message = (
                _("Finding accepted.")
                if decision.status == decision_service.ACCEPTED
                else _("Finding marked as a false positive.")
            )
    except decision_service.DecisionError as exc:
        db.session.rollback()
        flash(str(exc), "warning")
    else:
        db.session.commit()
        flash(message, "info")
    return redirect(_after_decision(assessment, finding))


@assessments_bp.get("/<uuid:assessment_id>/domain")
@login_required
def domain_detail(assessment_id: uuid.UUID) -> str:
    """What the latest scan collected about the domain itself (email security, ...)."""
    assessment = _get_accessible(assessment_id)
    scan = scan_service.get_latest_scan(db.session(), assessment.id)
    detail = host_view_service.get_domain_detail(db.session(), scan) if scan else None
    return render_template("assessments/domain.html", assessment=assessment, detail=detail)


@assessments_bp.post("/<uuid:assessment_id>/hosts")
@login_required
def add_hosts(assessment_id: uuid.UUID) -> Response:
    """Add hostnames by hand; they join every later scan."""
    assessment = _get_accessible(assessment_id)
    if (refusal := _archived_refusal(assessment)) is not None:
        return refusal
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
    if (refusal := _archived_refusal(assessment)) is not None:
        return refusal
    hostname = request.form.get("hostname", "")
    if assessment_service.remove_manual_host(db.session(), assessment, hostname):
        db.session.commit()
        flash(_("Removed %(host)s.", host=hostname), "info")
    return redirect(url_for("assessments.detail", assessment_id=assessment.id))
