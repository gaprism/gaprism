"""Tests for Assessment Overview and live HTMX scan progress updates (Story 5.1)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from flask import Flask, g
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import Membership, User, Workspace
from app.models.check import CheckResult, Finding
from app.models.discovery import Host
from app.models.grant import AssessmentGrant
from app.models.job import Job
from app.models.scan_run import ScanRun
from app.service.access.context import ActorContext


def _setup_test_assessment(
    db_session: Session,
) -> tuple[Workspace, User, Assessment, ActorContext]:
    """Helper to create a test workspace, user, and assessment with owner grant."""
    ws = Workspace(name=f"SecOps Workspace {uuid.uuid4().hex[:6]}", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(
        email=f"analyst_{uuid.uuid4().hex[:8]}@secops.ch",
        password="hash_password",
        active=True,
    )
    db_session.add(user)
    db_session.flush()

    mem = Membership(workspace_id=ws.id, user_id=user.id, role="member", active=True)
    db_session.add(mem)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="SecureSaaS AG",
        scope_ascii="securesaas.ch",
        scope_display="securesaas.ch",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    grant = AssessmentGrant(
        workspace_id=ws.id,
        assessment_id=assessment.id,
        user_id=user.id,
        role="analyst",
        can_download=True,
        granted_by=user.id,
    )
    db_session.add(grant)
    db_session.commit()

    actor = ActorContext.from_user(user, workspace_id=ws.id)
    return ws, user, assessment, actor


class TestAssessmentOverview:
    def test_overview_renders_summary_cards(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        ws, user, assessment, actor = _setup_test_assessment(db_session)

        # Add hosts
        host1 = Host(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            name_ascii="api.securesaas.ch",
            name_display="api.securesaas.ch",
        )
        host2 = Host(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            name_ascii="app.securesaas.ch",
            name_display="app.securesaas.ch",
        )
        db_session.add_all([host1, host2])
        db_session.flush()

        # Add scan run
        run = ScanRun(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            requested_by=user.id,
            request_key="req_overview_01",
            target_domain="securesaas.ch",
            scope_snapshot={"scope": "securesaas.ch"},
            status="completed",
        )
        db_session.add(run)
        db_session.flush()

        # Add CheckResults
        cr_geo1 = CheckResult(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            host_id=host1.id,
            logical_check_key="geoip:api.securesaas.ch",
            subject_kind="hostname",
            check_type="geoip",
            status="succeeded",
            verdict="match",
            payload={
                "country_code": "CH",
                "country_name": "Switzerland",
                "is_eu": False,
                "as_org": "Exoscale AG",
            },
        )
        cr_tls1 = CheckResult(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            host_id=host1.id,
            logical_check_key="tls:api.securesaas.ch",
            subject_kind="hostname",
            check_type="tls",
            status="succeeded",
            verdict="valid",
            payload={"days_until_expiration": 65},
        )
        cr_shodan1 = CheckResult(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            host_id=host1.id,
            logical_check_key="shodan:api.securesaas.ch",
            subject_kind="hostname",
            check_type="shodan",
            status="succeeded",
            payload={"ports": [443, 8443]},
        )
        db_session.add_all([cr_geo1, cr_tls1, cr_shodan1])

        # Add Findings (with separated attribution)
        f1 = Finding(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            host_id=host1.id,
            rule_id="HTTP_SECURITY_HEADERS",
            rule_version="1.0",
            subject_key="api.securesaas.ch",
            severity="low",
            confidence="high",
            attribution="hostname_supported",
            message_key="Missing Content-Security-Policy header",
            message_parameters={},
        )
        f2 = Finding(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            host_id=host1.id,
            rule_id="SHODAN_CVE_OBSERVED",
            rule_version="1.0",
            subject_key="api.securesaas.ch",
            severity="medium",
            confidence="high",
            attribution="shared_infrastructure",
            message_key="CVE-2023-1234 on shared edge",
            message_parameters={},
        )
        db_session.add_all([f1, f2])
        db_session.commit()

        # Render overview
        resp = client.get(
            f"/assessments/{assessment.id}",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Check location card and invariant disclaimer
        assert "Switzerland" in html
        assert "CH" in html
        assert "Observed public IP location, not contractual data storage guarantee" in html

        # Check provider card
        assert "Exoscale AG" in html

        # Check security signals
        assert "Security Signals" in html or "Security Observations" in html
        assert "TLS Certificates Valid" in html
        assert "Shared IP" in html
        assert "Missing Security Headers" in html

    def test_progress_htmx_polling_active_state(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        ws, user, assessment, actor = _setup_test_assessment(db_session)

        # Active running scan
        run = ScanRun(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            requested_by=user.id,
            request_key="req_active_01",
            target_domain="securesaas.ch",
            scope_snapshot={"scope": "securesaas.ch"},
            status="running",
            started_at=datetime.now(UTC),
        )
        db_session.add(run)
        db_session.flush()

        # Add jobs
        job1 = Job(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            job_type="tls_probe",
            logical_key="tls_probe_1",
            payload={"hostname": "api.securesaas.ch"},
            status="running",
        )
        job2 = Job(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            run_id=run.id,
            job_type="geoip_lookup",
            logical_key="geoip_1",
            payload={"ip": "1.2.3.4"},
            status="completed",
        )
        db_session.add_all([job1, job2])
        db_session.commit()

        resp = client.get(
            f"/assessments/{assessment.id}/progress",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Must contain Running badge and HTMX polling trigger
        assert "Running" in html
        assert 'hx-trigger="every 2s"' in html
        assert f'hx-get="/assessments/{assessment.id}/progress"' in html
        assert 'Completed Jobs' in html

    def test_progress_htmx_terminal_state_halts_polling(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        ws, user, assessment, actor = _setup_test_assessment(db_session)

        # Completed terminal run
        run = ScanRun(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            requested_by=user.id,
            request_key="req_term_01",
            target_domain="securesaas.ch",
            scope_snapshot={"scope": "securesaas.ch"},
            status="completed",
            started_at=datetime.now(UTC),
            terminal_at=datetime.now(UTC),
        )
        db_session.add(run)
        db_session.commit()

        resp = client.get(
            f"/assessments/{assessment.id}/progress",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Completed badge must be present and polling trigger must NOT be present
        assert "Completed" in html
        assert 'hx-trigger="every 2s"' not in html

    def test_overview_unauthorized_access_denied(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        ws, user, assessment, actor = _setup_test_assessment(db_session)

        # Create foreign user without grant
        foreign_user = User(
            email=f"foreign_{uuid.uuid4().hex[:8]}@other.com",
            password="pwd",
            active=True,
        )
        db_session.add(foreign_user)
        db_session.flush()
        db_session.add(
            Membership(workspace_id=ws.id, user_id=foreign_user.id, role="member", active=True)
        )
        db_session.commit()

        resp = client.get(
            f"/assessments/{assessment.id}",
            headers={
                "X-Test-Actor-Id": str(foreign_user.id),
                "X-Test-Workspace-Id": str(ws.id),
            },
        )
        # Foreign user with no grant must receive 404 or 403 (ACC-01)
        assert resp.status_code in (403, 404)
