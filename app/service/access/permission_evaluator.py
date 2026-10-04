"""Permission evaluation service enforcing object-level assessment and report grants."""

from datetime import datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from app.extensions import db
from app.models.assessment import Assessment, ReportVersion
from app.models.base import utc_now
from app.models.grant import AssessmentGrant, ReportGrant
from app.service.access.context import ActorContext


class ActionEnum(StrEnum):
    """Actions subject to object-level and workspace-level authorization."""

    READ_CASE = "read_case"
    READ_SOURCE_EVIDENCE = "read_source_evidence"
    DOWNLOAD_SOURCE_EVIDENCE = "download_source_evidence"
    START_CANCEL_SCAN = "start_cancel_scan"
    ADD_TECHNICAL_ANNOTATION = "add_technical_annotation"
    PREPARE_REPORT_DRAFT = "prepare_report_draft"
    READ_DRAFT_REPORTS = "read_draft_reports"
    APPROVE_REPORT = "approve_report"
    ISSUE_REPORT = "issue_report"
    READ_ISSUED_REPORTS = "read_issued_reports"
    DOWNLOAD_ISSUED_REPORT = "download_issued_report"
    MANAGE_GRANTS = "manage_grants"
    RECORD_TPRM_HANDOFF = "record_tprm_handoff"
    MANAGE_CONFIG = "manage_config"


def check_permission(
    actor: ActorContext,
    target: Assessment | ReportVersion | None,
    action: ActionEnum,
    session: Session | None = None,
    at_time: datetime | None = None,
    four_eyes_enabled: bool = False,
) -> bool:
    """Evaluate whether an actor has permission to perform an action on a target object.

    Enforces:
    - INV-01: A role never grants access to an unrelated assessment.
    - INV-02: Report-only access never grants underlying case, job, host or raw-artifact access.
    - INV-09: Access expires at the policy deadline even if physical deletion is delayed.
    """
    db_session = session or db.session

    # System/team configuration check
    if action == ActionEnum.MANAGE_CONFIG:
        return actor.is_admin

    if target is None:
        return False

    # Enforce workspace boundary: target must belong to actor's workspace
    if target.workspace_id != actor.workspace_id:
        return False

    if isinstance(target, Assessment):
        grant = (
            db_session.query(AssessmentGrant)
            .filter_by(
                workspace_id=actor.workspace_id,
                assessment_id=target.id,
                user_id=actor.user_id,
            )
            .first()
        )
        if not grant or not grant.is_active(at_time):
            return False

        return _evaluate_assessment_grant(grant, action)

    if isinstance(target, ReportVersion):
        if target.expires_at is not None and target.expires_at <= (at_time or utc_now()):
            return False
        # Path 1: Check if actor holds an assessment grant for the parent assessment
        case_grant = (
            db_session.query(AssessmentGrant)
            .filter_by(
                workspace_id=actor.workspace_id,
                assessment_id=target.assessment_id,
                user_id=actor.user_id,
            )
            .first()
        )

        if case_grant and case_grant.is_active(at_time):
            if action == ActionEnum.APPROVE_REPORT:
                if four_eyes_enabled and target.preparer_id == actor.user_id:
                    # Four-eyes governance: preparer cannot self-approve
                    return False
                return case_grant.role in ("owner", "reviewer")

            if action == ActionEnum.READ_DRAFT_REPORTS:
                return case_grant.role in ("owner", "analyst", "reviewer", "viewer")

            return _evaluate_assessment_grant(case_grant, action)

        # Path 2: Check narrow exact-version report grant (INV-02)
        report_grant = (
            db_session.query(ReportGrant)
            .filter_by(
                workspace_id=actor.workspace_id,
                report_version_id=target.id,
                user_id=actor.user_id,
            )
            .first()
        )

        if not report_grant or not report_grant.is_active(at_time):
            return False

        # Report-only grants require an issued report version
        if target.state != "issued":
            return False

        if action == ActionEnum.READ_ISSUED_REPORTS:
            return True
        elif action == ActionEnum.DOWNLOAD_ISSUED_REPORT:
            return report_grant.can_download

        # Report-only recipient cannot access any other case or draft actions (INV-02)
        return False

    return False


def _evaluate_assessment_grant(grant: AssessmentGrant, action: ActionEnum) -> bool:
    """Evaluate action permission for an active AssessmentGrant."""
    role = grant.role

    if action in (
        ActionEnum.READ_CASE,
        ActionEnum.READ_SOURCE_EVIDENCE,
        ActionEnum.READ_DRAFT_REPORTS,
        ActionEnum.READ_ISSUED_REPORTS,
    ):
        return role in ("owner", "analyst", "reviewer", "viewer")

    if action == ActionEnum.DOWNLOAD_SOURCE_EVIDENCE:
        return grant.can_download and role in ("owner", "analyst", "reviewer", "viewer")

    if action == ActionEnum.DOWNLOAD_ISSUED_REPORT:
        return grant.can_download and role in ("owner", "analyst", "reviewer", "viewer")

    if action in (ActionEnum.START_CANCEL_SCAN, ActionEnum.PREPARE_REPORT_DRAFT):
        return role in ("owner", "analyst")

    if action == ActionEnum.ADD_TECHNICAL_ANNOTATION:
        return role in ("owner", "analyst", "reviewer")

    if action == ActionEnum.APPROVE_REPORT:
        return role in ("owner", "reviewer")

    if action in (ActionEnum.ISSUE_REPORT, ActionEnum.MANAGE_GRANTS):
        return role == "owner"

    if action == ActionEnum.RECORD_TPRM_HANDOFF:
        return grant.can_download and role in ("owner", "analyst")

    return False
