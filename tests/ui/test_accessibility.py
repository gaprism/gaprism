"""Accessibility and keyboard navigation tests for Host Inventory (UX-01)."""

from __future__ import annotations

import re
import uuid

from flask import Flask, g
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import Membership, User, Workspace
from app.models.check import CheckResult, Finding
from app.models.discovery import Host
from app.models.grant import AssessmentGrant
from app.models.scan_run import ScanRun
from app.service.access.context import ActorContext


class TestAccessibilityAndUX:
    def test_ux_01_keyboard_landmarks_and_focus_attributes(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        """Verify ARIA landmarks, roles, and keyboard navigation elements (UX-01)."""
        ws = Workspace(name=f"Accessibility Workspace {uuid.uuid4().hex[:6]}", enabled=True)
        db_session.add(ws)
        db_session.flush()

        user = User(
            email=f"a11y_{uuid.uuid4().hex[:8]}@secops.ch",
            password="pwd",
            active=True,
        )
        db_session.add(user)
        db_session.flush()
        db_session.add(
            Membership(workspace_id=ws.id, user_id=user.id, role="member", active=True)
        )
        db_session.flush()

        assessment = Assessment(
            workspace_id=ws.id,
            supplier_label="Accessibility Target",
            scope_ascii="a11y.target.ch",
            scope_display="a11y.target.ch",
            created_by=user.id,
            owner_user_id=user.id,
            state="active",
        )
        db_session.add(assessment)
        db_session.flush()

        db_session.add(
            AssessmentGrant(
                workspace_id=ws.id,
                assessment_id=assessment.id,
                user_id=user.id,
                role="analyst",
                can_download=True,
                granted_by=user.id,
            )
        )

        host = Host(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            name_ascii="gateway.a11y.target.ch",
            name_display="gateway.a11y.target.ch",
        )
        db_session.add(host)
        db_session.commit()

        actor = ActorContext.from_user(user, workspace_id=ws.id)

        # 1. Main hosts page
        resp = client.get(
            f"/assessments/{assessment.id}/hosts",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Check ARIA Landmarks
        assert 'role="banner"' in html
        assert 'role="navigation"' in html
        assert 'role="main"' in html
        assert 'role="region"' in html
        assert 'aria-label="Host Inventory Table"' in html

        # Check keyboard accessibility attributes (tabindex)
        tabindex_matches = re.findall(r'tabindex="0"', html)
        assert len(tabindex_matches) >= 3, "Expected interactive elements with tabindex=0"

        # Check labels / aria-labels
        assert 'aria-label="Inspect details for gateway.a11y.target.ch"' in html

        # 2. Host detail modal
        detail_resp = client.get(
            f"/assessments/{assessment.id}/hosts/{host.id}",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert detail_resp.status_code == 200
        detail_html = detail_resp.get_data(as_text=True)

        # Check modal ARIA roles
        assert 'role="dialog"' in detail_html
        assert 'aria-modal="true"' in detail_html
        assert 'aria-labelledby="host-modal-title"' in detail_html
        assert 'aria-label="Close modal"' in detail_html

    def test_target_supplied_strings_html_escaped(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        """Verify target-supplied input and strings are safely escaped against XSS."""
        ws = Workspace(name=f"Escaping Workspace {uuid.uuid4().hex[:6]}", enabled=True)
        db_session.add(ws)
        db_session.flush()

        user = User(
            email=f"xss_{uuid.uuid4().hex[:8]}@secops.ch",
            password="pwd",
            active=True,
        )
        db_session.add(user)
        db_session.flush()
        db_session.add(
            Membership(workspace_id=ws.id, user_id=user.id, role="member", active=True)
        )
        db_session.flush()

        assessment = Assessment(
            workspace_id=ws.id,
            supplier_label="<script>alert('xss')</script> Escaped Corp",
            scope_ascii="xss-test.target.ch",
            scope_display="xss-test.target.ch",
            created_by=user.id,
            owner_user_id=user.id,
            state="active",
        )
        db_session.add(assessment)
        db_session.flush()

        db_session.add(
            AssessmentGrant(
                workspace_id=ws.id,
                assessment_id=assessment.id,
                user_id=user.id,
                role="analyst",
                can_download=True,
                granted_by=user.id,
            )
        )

        host = Host(
            workspace_id=ws.id,
            assessment_id=assessment.id,
            name_ascii="api.xss-test.target.ch",
            name_display="<img src=x onerror=alert(1)>",
        )
        db_session.add(host)
        db_session.commit()

        actor = ActorContext.from_user(user, workspace_id=ws.id)

        resp = client.get(
            f"/assessments/{assessment.id}/hosts",
            headers={
                "X-Test-Actor-Id": str(actor.user_id),
                "X-Test-Workspace-Id": str(actor.workspace_id),
            },
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Ensure raw unescaped script tag is NOT in the response
        assert "<script>alert('xss')</script>" not in html
        assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "&lt;script&gt;alert('xss')&lt;/script&gt;" in html
