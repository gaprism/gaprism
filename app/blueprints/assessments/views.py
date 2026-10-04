"""Views and routes for Assessment Overview, Progress, Host Inventory, and Annotations."""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from flask import (
    Blueprint,
    abort,
    g,
    render_template,
    request,
    session,
)
from flask_security import current_user
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.extensions import db
from app.models.annotation import FindingAnnotation
from app.models.assessment import Assessment
from app.models.auth import User
from app.models.check import CheckResult, Finding
from app.models.discovery import Host
from app.models.job import Job
from app.models.scan_run import ScanRun
from app.service.access.context import ActorContext
from app.service.access.permission_evaluator import ActionEnum, check_permission
from app.service.assessment.annotation import (
    AnnotationSchema,
    OptimisticLockConflictError,
    create_or_update_annotation,
)

assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")


def _get_db() -> Session:
    """Retrieve the application-scoped database session."""
    return db.session()


def _get_current_actor() -> ActorContext:
    """Retrieve actor context from request globals or authenticated session."""
    if hasattr(g, "actor") and isinstance(g.actor, ActorContext):
        return g.actor

    # Identity must come exclusively from Flask-Security's completed login flow.
    # Test helpers belong in tests, never in a request-header authentication path.
    if not current_user.is_authenticated or not current_user.is_active:
        abort(401, description="Authentication required.")
    user = current_user._get_current_object()
    if not isinstance(user, User):
        abort(401, description="Authentication required.")

    active_memberships = [m for m in user.memberships if m.active and m.workspace.enabled]
    if not active_memberships:
        abort(403, description="Active workspace membership required.")
    try:
        workspace_id = (
            uuid.UUID(str(session["workspace_id"]))
            if "workspace_id" in session
            else active_memberships[0].workspace_id
        )
        authenticated_at = session.get("fs_paa")
        freshness = (
            datetime.fromtimestamp(authenticated_at, UTC)
            if isinstance(authenticated_at, (int, float))
            else datetime.min.replace(tzinfo=UTC)
        )
        actor = ActorContext.from_user(user, workspace_id, auth_freshness=freshness)
    except (ValueError, TypeError, OverflowError, PermissionError):
        abort(403, description="Active workspace membership required.")
    g.actor = actor
    return actor


@dataclass(frozen=True)
class HostItemView:
    """View model for a row in the host inventory table."""

    host: Host
    tls_status: str  # 'valid', 'invalid', 'expired', 'untested'
    tls_reason: str | None
    tls_days_left: int | None
    country_code: str | None
    country_name: str | None
    provider: str | None
    as_org: str | None
    ports: list[int]
    max_severity: str | None


def _get_latest_run(assessment_id: uuid.UUID) -> ScanRun | None:
    """Get the most recent scan run for an assessment."""
    s = _get_db()
    stmt = (
        select(ScanRun)
        .where(ScanRun.assessment_id == assessment_id)
        .order_by(ScanRun.created_at.desc())
        .limit(1)
    )
    return s.scalar(stmt)


def _compute_progress_stats(assessment_id: uuid.UUID, run: ScanRun | None) -> dict[str, int]:
    """Compute progress counts for active and completed jobs."""
    s = _get_db()
    hosts_count = (
        s.scalar(select(func.count(Host.id)).where(Host.assessment_id == assessment_id)) or 0
    )

    if run is None:
        return {
            "hosts_count": hosts_count,
            "completed_jobs": 0,
            "pending_jobs": 0,
            "failed_jobs": 0,
        }

    job_counts = dict(
        s.execute(
            select(Job.status, func.count(Job.id)).where(Job.run_id == run.id).group_by(Job.status)
        ).all()
    )

    completed = (
        job_counts.get("completed", 0)
        + job_counts.get("failed", 0)
        + job_counts.get("skipped", 0)
        + job_counts.get("cancelled", 0)
    )
    pending = (
        job_counts.get("queued", 0)
        + job_counts.get("running", 0)
        + job_counts.get("waiting_provider", 0)
    )
    failed = job_counts.get("failed", 0) + job_counts.get("skipped", 0)

    return {
        "hosts_count": hosts_count,
        "completed_jobs": completed,
        "pending_jobs": pending,
        "failed_jobs": failed,
    }


def _compute_overview_summary(assessment_id: uuid.UUID, run_id: uuid.UUID | None) -> dict[str, Any]:
    """Calculate structured summary metrics for Location, Providers, and Security."""
    s = _get_db()
    # 1. Location summary from GeoIP check results
    geoip_stmt = select(CheckResult).where(
        CheckResult.assessment_id == assessment_id,
        CheckResult.check_type == "geoip",
        CheckResult.status == "succeeded",
    )
    if run_id:
        geoip_stmt = geoip_stmt.where(CheckResult.run_id == run_id)

    geoip_results = s.scalars(geoip_stmt).all()

    country_map: dict[str, dict[str, Any]] = {}
    provider_map: dict[str, dict[str, Any]] = {}

    for res in geoip_results:
        payload = res.payload
        cc = payload.get("country_code")
        cname = payload.get("country_name", cc)
        is_eu = payload.get("is_eu", False)

        if cc:
            if cc not in country_map:
                country_map[cc] = {
                    "country_code": cc,
                    "country_name": cname,
                    "is_eu": is_eu,
                    "host_count": 0,
                }
            country_map[cc]["host_count"] += 1

        as_org = payload.get("as_org")
        if as_org:
            if as_org not in provider_map:
                provider_map[as_org] = {
                    "name": as_org,
                    "category": "Cloud / Hosting",
                    "host_count": 0,
                }
            provider_map[as_org]["host_count"] += 1

    sorted_countries = sorted(
        country_map.values(), key=lambda c: int(c["host_count"]), reverse=True
    )
    sorted_providers = sorted(
        provider_map.values(), key=lambda p: int(p["host_count"]), reverse=True
    )

    # 2. Security Signals & TLS counts
    tls_stmt = select(CheckResult).where(
        CheckResult.assessment_id == assessment_id,
        CheckResult.check_type == "tls",
    )
    if run_id:
        tls_stmt = tls_stmt.where(CheckResult.run_id == run_id)

    tls_results = s.scalars(tls_stmt).all()
    tls_total = len(tls_results)
    tls_valid = sum(1 for r in tls_results if r.verdict == "valid")
    tls_invalid = sum(1 for r in tls_results if r.verdict == "invalid")

    # Shodan Open Ports
    shodan_stmt = select(CheckResult).where(
        CheckResult.assessment_id == assessment_id,
        CheckResult.check_type == "shodan",
        CheckResult.status == "succeeded",
    )
    if run_id:
        shodan_stmt = shodan_stmt.where(CheckResult.run_id == run_id)

    shodan_results = s.scalars(shodan_stmt).all()
    unique_ports: set[int] = set()
    for sr in shodan_results:
        ports = sr.payload.get("ports", [])
        if isinstance(ports, list):
            for p in ports:
                if isinstance(p, int):
                    unique_ports.add(p)

    # Findings query
    finding_stmt = select(Finding).where(Finding.assessment_id == assessment_id)
    if run_id:
        finding_stmt = finding_stmt.where(Finding.run_id == run_id)

    findings = s.scalars(finding_stmt).all()
    total_findings = len(findings)

    cve_hostname_count = sum(
        1
        for f in findings
        if f.rule_id == "SHODAN_CVE_OBSERVED" and f.attribution == "hostname_supported"
    )
    cve_shared_count = sum(
        1
        for f in findings
        if f.rule_id == "SHODAN_CVE_OBSERVED"
        and f.attribution in ("shared_infrastructure", "ip_only")
    )
    missing_headers_count = sum(
        1 for f in findings if "HEADER" in f.rule_id or f.rule_id == "HTTP_SECURITY_HEADERS"
    )

    return {
        "location": {"countries": sorted_countries},
        "providers": {"provider_list": sorted_providers},
        "security": {
            "tls_total": tls_total,
            "tls_valid": tls_valid,
            "tls_invalid": tls_invalid,
            "open_ports_count": len(unique_ports),
            "missing_headers_count": missing_headers_count,
            "cve_hostname_count": cve_hostname_count,
            "cve_shared_count": cve_shared_count,
            "total_findings": total_findings,
        },
    }


@assessments_bp.route("/<uuid:id>", methods=["GET"])
def overview(id: uuid.UUID) -> str:
    """Render Assessment Overview page."""
    actor = _get_current_actor()
    s = _get_db()

    assessment = s.scalar(select(Assessment).where(Assessment.id == id))
    if assessment is None or not check_permission(
        actor, assessment, ActionEnum.READ_CASE, session=s
    ):
        abort(404, description="Assessment not found.")

    latest_run = _get_latest_run(id)
    progress_stats = _compute_progress_stats(id, latest_run)
    summary = _compute_overview_summary(id, latest_run.id if latest_run else None)

    return render_template(
        "assessments/overview.html",
        assessment=assessment,
        latest_run=latest_run,
        progress_stats=progress_stats,
        summary=summary,
        total_hosts_count=progress_stats["hosts_count"],
    )


@assessments_bp.route("/<uuid:id>/progress", methods=["GET"])
def progress(id: uuid.UUID) -> str:
    """HTMX polling partial for scan progress."""
    actor = _get_current_actor()
    s = _get_db()

    assessment = s.scalar(select(Assessment).where(Assessment.id == id))
    if assessment is None or not check_permission(
        actor, assessment, ActionEnum.READ_CASE, session=s
    ):
        abort(404, description="Assessment not found.")

    latest_run = _get_latest_run(id)
    progress_stats = _compute_progress_stats(id, latest_run)

    return render_template(
        "assessments/partials/progress.html",
        assessment=assessment,
        latest_run=latest_run,
        progress_stats=progress_stats,
    )


@assessments_bp.route("/<uuid:id>/hosts", methods=["GET"])
def host_inventory(id: uuid.UUID) -> str:
    """Searchable, paginated host inventory table."""
    actor = _get_current_actor()
    s = _get_db()

    assessment = s.scalar(select(Assessment).where(Assessment.id == id))
    if assessment is None or not check_permission(
        actor, assessment, ActionEnum.READ_CASE, session=s
    ):
        abort(404, description="Assessment not found.")

    # Query params
    page = request.args.get("page", default=1, type=int)
    if page < 1:
        page = 1
    per_page = request.args.get("per_page", default=50, type=int)
    if per_page < 1:
        per_page = 50
    elif per_page > 100:
        per_page = 100

    q_filter = request.args.get("q", default="", type=str).strip().lower()
    country_filter = request.args.get("country", default="", type=str).strip().upper()
    tls_status_filter = request.args.get("tls_status", default="", type=str).strip().lower()
    severity_filter = request.args.get("severity", default="", type=str).strip().lower()

    # Query all hosts for this assessment using index (assessment_id, name_ascii)
    base_host_query = select(Host).where(Host.assessment_id == id)
    if q_filter:
        base_host_query = base_host_query.where(Host.name_ascii.ilike(f"%{q_filter}%"))

    # Order deterministically for keyset/offset pagination
    base_host_query = base_host_query.order_by(Host.name_ascii.asc())

    all_matched_hosts = s.scalars(base_host_query).all()

    # Pre-fetch check results and findings for this assessment
    check_results = s.scalars(select(CheckResult).where(CheckResult.assessment_id == id)).all()
    findings = s.scalars(select(Finding).where(Finding.assessment_id == id)).all()

    checks_by_host: dict[uuid.UUID, dict[str, CheckResult]] = {}
    for cr in check_results:
        if cr.host_id:
            if cr.host_id not in checks_by_host:
                checks_by_host[cr.host_id] = {}
            checks_by_host[cr.host_id][cr.check_type] = cr

    findings_by_host: dict[uuid.UUID, list[Finding]] = {}
    for f in findings:
        if f.host_id:
            if f.host_id not in findings_by_host:
                findings_by_host[f.host_id] = []
            findings_by_host[f.host_id].append(f)

    # Filter available options for filter dropdowns
    available_countries: set[str] = set()
    for cr_dict in checks_by_host.values():
        if "geoip" in cr_dict:
            cc = cr_dict["geoip"].payload.get("country_code")
            if cc:
                available_countries.add(str(cc))

    severity_order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }

    # Build HostItemView list
    filtered_items: list[HostItemView] = []
    for host in all_matched_hosts:
        h_checks = checks_by_host.get(host.id, {})
        h_findings = findings_by_host.get(host.id, [])

        # TLS info
        tls_res = h_checks.get("tls")
        tls_status = "untested"
        tls_reason = None
        tls_days_left = None
        if tls_res:
            if tls_res.verdict == "valid":
                tls_status = "valid"
                tls_days_left = tls_res.payload.get("days_until_expiration")
            elif "EXPIRED" in str(tls_res.reason_code):
                tls_status = "expired"
                tls_reason = tls_res.reason_code
            else:
                tls_status = "invalid"
                tls_reason = tls_res.reason_code

        # GeoIP info
        geoip_res = h_checks.get("geoip")
        country_code = None
        country_name = None
        provider = None
        as_org = None
        if geoip_res:
            country_code = geoip_res.payload.get("country_code")
            country_name = geoip_res.payload.get("country_name")
            as_org = geoip_res.payload.get("as_org")

        # Shodan info
        shodan_res = h_checks.get("shodan")
        ports: list[int] = []
        if shodan_res:
            raw_ports = shodan_res.payload.get("ports", [])
            if isinstance(raw_ports, list):
                ports = [p for p in raw_ports if isinstance(p, int)]

        # Max Severity
        max_sev = None
        if h_findings:
            sorted_f = sorted(
                h_findings,
                key=lambda f: severity_order.get(f.severity.lower(), 0),
                reverse=True,
            )
            max_sev = sorted_f[0].severity

        # Apply secondary filters
        if country_filter and country_code != country_filter:
            continue
        if tls_status_filter and tls_status != tls_status_filter:
            continue
        if severity_filter and (not max_sev or max_sev.lower() != severity_filter):
            continue

        filtered_items.append(
            HostItemView(
                host=host,
                tls_status=tls_status,
                tls_reason=tls_reason,
                tls_days_left=tls_days_left,
                country_code=country_code,
                country_name=country_name,
                provider=provider,
                as_org=as_org,
                ports=ports,
                max_severity=max_sev,
            )
        )

    total_hosts = len(filtered_items)
    total_pages = math.ceil(total_hosts / per_page) if total_hosts > 0 else 1
    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_hosts)
    page_items = filtered_items[start_idx:end_idx]

    pagination = {
        "page": page,
        "per_page": per_page,
        "total_hosts": total_hosts,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "start_idx": start_idx + 1 if total_hosts > 0 else 0,
        "end_idx": end_idx,
    }

    current_filters = {
        "q": q_filter,
        "country": country_filter,
        "tls_status": tls_status_filter,
        "severity": severity_filter,
    }

    filter_options = {
        "countries": sorted(available_countries),
    }

    template_context = {
        "assessment": assessment,
        "hosts": page_items,
        "pagination": pagination,
        "current_filters": current_filters,
        "filter_options": filter_options,
    }

    # If HTMX request, return the table partial directly
    if request.headers.get("HX-Request") == "true":
        return render_template("assessments/partials/host_table.html", **template_context)

    return render_template("assessments/hosts.html", **template_context)


@assessments_bp.route("/<uuid:id>/hosts/<uuid:host_id>", methods=["GET"])
def host_detail(id: uuid.UUID, host_id: uuid.UUID) -> str:
    """Render Host Detail modal / drawer partial."""
    actor = _get_current_actor()
    s = _get_db()

    assessment = s.scalar(select(Assessment).where(Assessment.id == id))
    if assessment is None or not check_permission(
        actor, assessment, ActionEnum.READ_CASE, session=s
    ):
        abort(404, description="Assessment not found.")

    host = s.scalar(select(Host).where(Host.id == host_id, Host.assessment_id == id))
    if host is None:
        abort(404, description="Host not found.")

    # Get all check results for this host
    checks = s.scalars(
        select(CheckResult).where(CheckResult.assessment_id == id, CheckResult.host_id == host_id)
    ).all()

    checks_by_type = {c.check_type: c for c in checks}

    # Get findings with eager loaded annotations
    findings = s.scalars(
        select(Finding).where(Finding.assessment_id == id, Finding.host_id == host_id)
    ).all()

    return render_template(
        "assessments/partials/host_detail.html",
        assessment=assessment,
        host=host,
        tls_check=checks_by_type.get("tls"),
        geoip_check=checks_by_type.get("geoip"),
        shodan_check=checks_by_type.get("shodan"),
        screenshot_check=checks_by_type.get("screenshot"),
        findings=findings,
    )


@assessments_bp.route("/<uuid:id>/findings/<uuid:finding_id>/annotate", methods=["POST"])
def annotate_finding(id: uuid.UUID, finding_id: uuid.UUID) -> tuple[str, int]:
    """Submit analyst annotation with optimistic concurrency control."""
    actor = _get_current_actor()
    s = _get_db()

    assessment = s.scalar(select(Assessment).where(Assessment.id == id))
    if assessment is None:
        abort(404, description="Assessment not found.")

    if not check_permission(actor, assessment, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=s):
        abort(403, description="Permission denied.")

    finding = s.scalar(select(Finding).where(Finding.id == finding_id, Finding.assessment_id == id))
    if finding is None:
        abort(404, description="Finding not found.")

    version_id = request.form.get("version_id", default=1, type=int)
    justification = request.form.get("justification", default="", type=str)
    revised_severity = request.form.get("revised_severity", default=None, type=str)
    if not revised_severity:
        revised_severity = None
    is_false_positive = request.form.get("is_false_positive") in ("true", "1", "on")

    try:
        schema = AnnotationSchema(
            justification=justification,
            revised_severity=revised_severity,
            is_false_positive=is_false_positive,
        )
        annotation = create_or_update_annotation(
            finding_id=finding.id,
            data=schema,
            expected_version=version_id,
            actor=actor,
            session=s,
        )
        s.commit()

        html = render_template(
            "assessments/partials/annotation_form.html",
            assessment=assessment,
            finding=finding,
            annotation=annotation,
            conflict_error=None,
        )
        return html, 200

    except OptimisticLockConflictError as e:
        s.rollback()
        # Fetch current finding and annotation to display
        current_finding = s.scalar(select(Finding).where(Finding.id == finding_id))
        current_ann = s.scalar(
            select(FindingAnnotation).where(FindingAnnotation.finding_id == finding_id)
        )
        current_assessment = s.scalar(select(Assessment).where(Assessment.id == id))
        html = render_template(
            "assessments/partials/annotation_form.html",
            assessment=current_assessment or assessment,
            finding=current_finding or finding,
            annotation=current_ann,
            conflict_error=str(e),
        )
        return html, 409

    except (ValidationError, ValueError) as e:
        s.rollback()
        current_finding = s.scalar(select(Finding).where(Finding.id == finding_id))
        current_ann = s.scalar(
            select(FindingAnnotation).where(FindingAnnotation.finding_id == finding_id)
        )
        current_assessment = s.scalar(select(Assessment).where(Assessment.id == id))
        html = render_template(
            "assessments/partials/annotation_form.html",
            assessment=current_assessment or assessment,
            finding=current_finding or finding,
            annotation=current_ann,
            conflict_error=f"Validation error: {e}",
        )
        return html, 400
