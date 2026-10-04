"""Acceptance test suite ACC-01: Two-case, multi-role authorization permission matrix."""

from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy.orm import Session

from app.models.assessment import Assessment, Report, ReportVersion
from app.models.auth import Membership, User, Workspace
from app.models.grant import AssessmentGrant, ReportGrant
from app.service.access.context import ActorContext
from app.service.access.permission_evaluator import ActionEnum, check_permission


@pytest.fixture
def access_environment(app: Flask, db_session: Session) -> dict[str, object]:
    """Setup 2 workspaces, 2 cases, 2 report versions, and 6 distinct user actors."""
    with app.app_context():
        # Workspaces
        ws1 = Workspace(name="Primary Workspace", enabled=True)
        ws2 = Workspace(name="Foreign Workspace", enabled=True)
        db_session.add_all([ws1, ws2])
        db_session.flush()

        # Users
        u_owner = User(email="owner@example.org", password="pwd", active=True)
        u_analyst = User(email="analyst@example.org", password="pwd", active=True)
        u_reviewer = User(email="reviewer@example.org", password="pwd", active=True)
        u_viewer = User(email="viewer@example.org", password="pwd", active=True)
        u_report_only = User(email="report_only@example.org", password="pwd", active=True)
        u_admin = User(email="admin_nogrant@example.org", password="pwd", active=True)
        u_foreign = User(email="foreign_user@example.org", password="pwd", active=True)

        db_session.add_all(
            [u_owner, u_analyst, u_reviewer, u_viewer, u_report_only, u_admin, u_foreign]
        )
        db_session.flush()

        # Memberships in ws1
        for u, role in [
            (u_owner, "member"),
            (u_analyst, "member"),
            (u_reviewer, "member"),
            (u_viewer, "member"),
            (u_report_only, "member"),
            (u_admin, "admin"),
        ]:
            db_session.add(Membership(workspace_id=ws1.id, user_id=u.id, role=role, active=True))

        # Membership in ws2
        db_session.add(
            Membership(workspace_id=ws2.id, user_id=u_foreign.id, role="member", active=True)
        )
        db_session.flush()

        # Case 1 (ws1)
        case1 = Assessment(
            workspace_id=ws1.id,
            supplier_label="Acme Corp",
            scope_ascii="acme.example.com",
            scope_display="acme.example.com",
            created_by=u_owner.id,
            owner_user_id=u_owner.id,
            state="active",
        )
        # Case 2 (ws1 - separate assessment)
        case2 = Assessment(
            workspace_id=ws1.id,
            supplier_label="Beta Corp",
            scope_ascii="beta.example.com",
            scope_display="beta.example.com",
            created_by=u_owner.id,
            owner_user_id=u_owner.id,
            state="active",
        )
        db_session.add_all([case1, case2])
        db_session.flush()

        # Grants for Case 1
        g_owner = AssessmentGrant(
            workspace_id=ws1.id,
            assessment_id=case1.id,
            user_id=u_owner.id,
            role="owner",
            can_download=True,
            granted_by=u_owner.id,
        )
        g_analyst = AssessmentGrant(
            workspace_id=ws1.id,
            assessment_id=case1.id,
            user_id=u_analyst.id,
            role="analyst",
            can_download=True,
            granted_by=u_owner.id,
        )
        g_reviewer = AssessmentGrant(
            workspace_id=ws1.id,
            assessment_id=case1.id,
            user_id=u_reviewer.id,
            role="reviewer",
            can_download=True,
            granted_by=u_owner.id,
        )
        g_viewer = AssessmentGrant(
            workspace_id=ws1.id,
            assessment_id=case1.id,
            user_id=u_viewer.id,
            role="viewer",
            can_download=False,
            granted_by=u_owner.id,
        )
        db_session.add_all([g_owner, g_analyst, g_reviewer, g_viewer])
        db_session.flush()

        # Reports on Case 1
        report1 = Report(workspace_id=ws1.id, assessment_id=case1.id, created_by=u_owner.id)
        db_session.add(report1)
        db_session.flush()

        # Version 1: Issued report
        rep_v1 = ReportVersion(
            workspace_id=ws1.id,
            report_id=report1.id,
            assessment_id=case1.id,
            version_number=1,
            snapshot_schema="1.0",
            snapshot_json={"findings": []},
            snapshot_hash="hash_v1",
            state="issued",
            preparer_id=u_analyst.id,
            policy_version="1.0",
        )
        # Version 2: Draft report (prepared by owner)
        rep_v2 = ReportVersion(
            workspace_id=ws1.id,
            report_id=report1.id,
            assessment_id=case1.id,
            version_number=2,
            snapshot_schema="1.0",
            snapshot_json={"findings": []},
            snapshot_hash="hash_v2",
            state="draft",
            preparer_id=u_owner.id,
            policy_version="1.0",
        )
        db_session.add_all([rep_v1, rep_v2])
        db_session.flush()

        # Narrow report grant on rep_v1 for u_report_only (can_download=True)
        rg = ReportGrant(
            workspace_id=ws1.id,
            report_version_id=rep_v1.id,
            user_id=u_report_only.id,
            can_download=True,
            granted_by=u_owner.id,
        )
        db_session.add(rg)
        db_session.commit()

        # Build ActorContexts
        return {
            "ws1": ws1,
            "ws2": ws2,
            "case1": case1,
            "case2": case2,
            "rep_v1": rep_v1,
            "rep_v2": rep_v2,
            "actor_owner": ActorContext.from_user(u_owner, ws1.id),
            "actor_analyst": ActorContext.from_user(u_analyst, ws1.id),
            "actor_reviewer": ActorContext.from_user(u_reviewer, ws1.id),
            "actor_viewer": ActorContext.from_user(u_viewer, ws1.id),
            "actor_report_only": ActorContext.from_user(u_report_only, ws1.id),
            "actor_admin": ActorContext.from_user(u_admin, ws1.id),
            "actor_foreign": ActorContext.from_user(u_foreign, ws2.id),
        }


def test_acc01_read_case(access_environment: dict[str, object], db_session: Session) -> None:
    """Verify Case 1 read permissions across all roles and isolation of admin without grant."""
    case1 = access_environment["case1"]
    assert isinstance(case1, Assessment)

    # Authorized case roles
    for role_name in ["actor_owner", "actor_analyst", "actor_reviewer", "actor_viewer"]:
        actor = access_environment[role_name]
        assert isinstance(actor, ActorContext)
        assert check_permission(actor, case1, ActionEnum.READ_CASE, session=db_session) is True

    # Report-only and admin without grant cannot read case contents (INV-01, INV-02)
    actor_ro = access_environment["actor_report_only"]
    assert isinstance(actor_ro, ActorContext)
    assert check_permission(actor_ro, case1, ActionEnum.READ_CASE, session=db_session) is False

    actor_admin = access_environment["actor_admin"]
    assert isinstance(actor_admin, ActorContext)
    assert check_permission(actor_admin, case1, ActionEnum.READ_CASE, session=db_session) is False

    actor_foreign = access_environment["actor_foreign"]
    assert isinstance(actor_foreign, ActorContext)
    assert check_permission(actor_foreign, case1, ActionEnum.READ_CASE, session=db_session) is False


def test_acc01_scans_and_annotations(
    access_environment: dict[str, object], db_session: Session
) -> None:
    """Verify scan start/cancel and technical annotation permissions."""
    case1 = access_environment["case1"]
    assert isinstance(case1, Assessment)

    # Scans: Owner & Analyst only
    actor_owner = access_environment["actor_owner"]
    actor_analyst = access_environment["actor_analyst"]
    actor_reviewer = access_environment["actor_reviewer"]
    actor_viewer = access_environment["actor_viewer"]
    assert isinstance(actor_owner, ActorContext)
    assert isinstance(actor_analyst, ActorContext)
    assert isinstance(actor_reviewer, ActorContext)
    assert isinstance(actor_viewer, ActorContext)

    assert (
        check_permission(actor_owner, case1, ActionEnum.START_CANCEL_SCAN, session=db_session)
        is True
    )
    assert (
        check_permission(actor_analyst, case1, ActionEnum.START_CANCEL_SCAN, session=db_session)
        is True
    )
    assert (
        check_permission(actor_reviewer, case1, ActionEnum.START_CANCEL_SCAN, session=db_session)
        is False
    )
    assert (
        check_permission(actor_viewer, case1, ActionEnum.START_CANCEL_SCAN, session=db_session)
        is False
    )

    # Annotations: Owner, Analyst & Reviewer
    assert (
        check_permission(
            actor_owner, case1, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=db_session
        )
        is True
    )
    assert (
        check_permission(
            actor_analyst, case1, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=db_session
        )
        is True
    )
    assert (
        check_permission(
            actor_reviewer, case1, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=db_session
        )
        is True
    )
    assert (
        check_permission(
            actor_viewer, case1, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=db_session
        )
        is False
    )


def test_acc01_approval_and_issuance_four_eyes(
    access_environment: dict[str, object], db_session: Session
) -> None:
    """Verify report approval, four-eyes constraint, and issuance permissions."""
    rep_v1 = access_environment["rep_v1"]  # preparer is analyst
    rep_v2 = access_environment["rep_v2"]  # preparer is owner
    assert isinstance(rep_v1, ReportVersion)
    assert isinstance(rep_v2, ReportVersion)

    actor_owner = access_environment["actor_owner"]
    actor_analyst = access_environment["actor_analyst"]
    actor_reviewer = access_environment["actor_reviewer"]
    assert isinstance(actor_owner, ActorContext)
    assert isinstance(actor_analyst, ActorContext)
    assert isinstance(actor_reviewer, ActorContext)

    # Approval on v1 (preparer=analyst): Owner and Reviewer can approve
    assert (
        check_permission(
            actor_owner,
            rep_v1,
            ActionEnum.APPROVE_REPORT,
            session=db_session,
            four_eyes_enabled=True,
        )
        is True
    )
    assert (
        check_permission(
            actor_reviewer,
            rep_v1,
            ActionEnum.APPROVE_REPORT,
            session=db_session,
            four_eyes_enabled=True,
        )
        is True
    )
    assert (
        check_permission(
            actor_analyst,
            rep_v1,
            ActionEnum.APPROVE_REPORT,
            session=db_session,
            four_eyes_enabled=True,
        )
        is False
    )

    # Approval on v2 (preparer=owner) under four-eyes governance: Owner CANNOT self-approve
    assert (
        check_permission(
            actor_owner,
            rep_v2,
            ActionEnum.APPROVE_REPORT,
            session=db_session,
            four_eyes_enabled=True,
        )
        is False
    )
    assert (
        check_permission(
            actor_reviewer,
            rep_v2,
            ActionEnum.APPROVE_REPORT,
            session=db_session,
            four_eyes_enabled=True,
        )
        is True
    )

    # Issuance: Only owner
    assert (
        check_permission(actor_owner, rep_v1, ActionEnum.ISSUE_REPORT, session=db_session) is True
    )
    assert (
        check_permission(actor_analyst, rep_v1, ActionEnum.ISSUE_REPORT, session=db_session)
        is False
    )
    assert (
        check_permission(actor_reviewer, rep_v1, ActionEnum.ISSUE_REPORT, session=db_session)
        is False
    )


def test_acc01_report_only_recipient_isolation(
    access_environment: dict[str, object], db_session: Session
) -> None:
    """Verify report-only recipients can only access their specific report version (INV-02)."""
    case1 = access_environment["case1"]
    rep_v1 = access_environment["rep_v1"]  # issued, granted
    rep_v2 = access_environment["rep_v2"]  # draft, not granted
    assert isinstance(case1, Assessment)
    assert isinstance(rep_v1, ReportVersion)
    assert isinstance(rep_v2, ReportVersion)

    actor_ro = access_environment["actor_report_only"]
    assert isinstance(actor_ro, ActorContext)

    # Allowed: reading and downloading issued report version 1
    assert (
        check_permission(actor_ro, rep_v1, ActionEnum.READ_ISSUED_REPORTS, session=db_session)
        is True
    )
    assert (
        check_permission(actor_ro, rep_v1, ActionEnum.DOWNLOAD_ISSUED_REPORT, session=db_session)
        is True
    )

    # Forbidden: draft version 2
    assert (
        check_permission(actor_ro, rep_v2, ActionEnum.READ_DRAFT_REPORTS, session=db_session)
        is False
    )
    assert (
        check_permission(actor_ro, rep_v2, ActionEnum.READ_ISSUED_REPORTS, session=db_session)
        is False
    )

    # Forbidden: underlying case data (INV-02)
    assert check_permission(actor_ro, case1, ActionEnum.READ_CASE, session=db_session) is False
    assert (
        check_permission(actor_ro, case1, ActionEnum.READ_SOURCE_EVIDENCE, session=db_session)
        is False
    )
    assert (
        check_permission(actor_ro, case1, ActionEnum.START_CANCEL_SCAN, session=db_session) is False
    )


def test_acc01_cross_case_isolation(
    access_environment: dict[str, object], db_session: Session
) -> None:
    """Verify that grants on Case 1 do not bleed into Case 2 (INV-01)."""
    case2 = access_environment["case2"]
    assert isinstance(case2, Assessment)

    # Analyst, Reviewer, Viewer on Case 1 have NO grant on Case 2
    for role_name in ["actor_analyst", "actor_reviewer", "actor_viewer", "actor_report_only"]:
        actor = access_environment[role_name]
        assert isinstance(actor, ActorContext)
        assert check_permission(actor, case2, ActionEnum.READ_CASE, session=db_session) is False
        assert (
            check_permission(actor, case2, ActionEnum.START_CANCEL_SCAN, session=db_session)
            is False
        )


def test_acc01_expired_grant(access_environment: dict[str, object], db_session: Session) -> None:
    """Verify expired grants immediately deny access even if row exists in DB (INV-09)."""
    case1 = access_environment["case1"]
    assert isinstance(case1, Assessment)

    actor_analyst = access_environment["actor_analyst"]
    assert isinstance(actor_analyst, ActorContext)

    # Set expiry in the past
    grant = (
        db_session.query(AssessmentGrant)
        .filter_by(assessment_id=case1.id, user_id=actor_analyst.user_id)
        .first()
    )
    assert grant is not None
    grant.expires_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.commit()

    # Access must be denied
    assert check_permission(actor_analyst, case1, ActionEnum.READ_CASE, session=db_session) is False


def test_expired_report_denied_to_case_and_report_recipients(
    access_environment: dict[str, object], db_session: Session
) -> None:
    report = access_environment["rep_v1"]
    assert isinstance(report, ReportVersion)
    report.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()
    for role in ("actor_owner", "actor_report_only"):
        actor = access_environment[role]
        assert isinstance(actor, ActorContext)
        for action in (ActionEnum.READ_ISSUED_REPORTS, ActionEnum.DOWNLOAD_ISSUED_REPORT):
            assert not check_permission(actor, report, action, session=db_session)
