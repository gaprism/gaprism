"""The audit log page. Thin: check that the person is an administrator, ask the service, render."""

from __future__ import annotations

from datetime import timedelta

from flask import abort, render_template, request
from flask_security import login_required

from app.blueprints.assessments.access import current_user_object, uuid_or_none
from app.blueprints.audit import audit_bp
from app.extensions import db
from app.models.base import utc_now
from app.service import assessments as assessment_service
from app.service import audit as audit_service

DAY_CHOICES = (7, 30, 90)  # "everything" is the default
MAX_USER_FILTER = 100

audit_bp.add_app_template_global(assessment_service.is_admin, "is_admin")
audit_bp.add_app_template_global(audit_service.action_label, "audit_action_label")
audit_bp.add_app_template_global(audit_service.group_label, "audit_group_label")
audit_bp.add_app_template_global(audit_service.facts, "audit_facts")


@audit_bp.get("/")
@login_required
def index() -> str:
    """Every entry of the audit log, newest first, filtered by what, who, which assessment, when."""
    if not assessment_service.is_admin(current_user_object()):
        abort(404)  # not for everyone: nothing here to confirm
    args = request.args
    group = args.get("group", "")
    group = group if group in audit_service.GROUPS else ""
    action = args.get("action", "")
    action = action if action in audit_service.ACTIONS else ""
    person = args.get("user", "")[:MAX_USER_FILTER].strip()
    window = args.get("days", type=int)
    window = window if window in DAY_CHOICES else None
    assessment_id = uuid_or_none(args.get("assessment", ""))
    filters = {
        "group": group,
        "action": action,
        "user": person,
        "assessment": assessment_id,
        "days": window,
    }
    page = audit_service.list_events(
        db.session(),
        group=group or None,
        action=action or None,
        actor=person or None,
        assessment_id=assessment_id,
        since=utc_now() - timedelta(days=window) if window else None,
        page=args.get("page", 1, type=int) or 1,
    )
    return render_template(
        "audit/index.html",
        page=page,
        filters=filters,
        names=audit_service.assessment_names(db.session(), page.items),
        groups=audit_service.GROUPS,
        actions=audit_service.ACTIONS,
        day_choices=DAY_CHOICES,
    )
