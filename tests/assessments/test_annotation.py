"""Tests for Finding Revision and Optimistic Locking Annotation Engine (Story 5.3)."""

from __future__ import annotations

import uuid

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import Membership, User, Workspace
from app.models.check import Finding
from app.models.grant import AssessmentGrant
from app.models.scan_run import ScanRun
from app.service.access.context import ActorContext
from app.service.assessment.annotation import (
    AnnotationSchema,
    OptimisticLockConflictError,
    create_or_update_annotation,
)
from tests.session_helpers import login_as


def _setup_annotation_environment(
    db_session: Session,
) -> tuple[Workspace, User, Assessment, Finding, ActorContext]:
    """Helper to set up assessment, finding, and analyst actor."""
    uid = uuid.uuid4().hex[:8]
    ws = Workspace(name=f"Annotation Workspace {uid}", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(email=f"analyst_{uid}@test.ch", password="hash_password", active=True)
    db_session.add(user)
    db_session.flush()

    mem = Membership(workspace_id=ws.id, user_id=user.id, role="member", active=True)
    db_session.add(mem)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor AG",
        scope_ascii=f"vendor-{uid}.ch",
        scope_display=f"vendor-{uid}.ch",
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
    db_session.flush()

    run = ScanRun(
        workspace_id=ws.id,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key=f"req_ann_{uid}",
        target_domain=f"vendor-{uid}.ch",
        scope_snapshot={"scope": f"vendor-{uid}.ch"},
        status="completed",
    )
    db_session.add(run)
    db_session.flush()

    finding = Finding(
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=run.id,
        rule_id="SHODAN_CVE_OBSERVED",
        rule_version="1.0",
        subject_key="api.vendor.ch",
        severity="high",
        confidence="high",
        attribution="shared_infrastructure",
        message_key="Observed CVE-2023-4567 on shared reverse proxy",
        message_parameters={"cve": "CVE-2023-4567"},
    )
    db_session.add(finding)
    db_session.commit()

    actor = ActorContext.from_user(user, workspace_id=ws.id)
    return ws, user, assessment, finding, actor


class TestAnnotationEngine:
    def test_create_initial_annotation(self, app: Flask, db_session: Session) -> None:
        _ws, user, _assessment, finding, actor = _setup_annotation_environment(db_session)

        with app.app_context():
            schema = AnnotationSchema(
                justification=(
                    "Confirmed shared Cloudflare reverse proxy; not vulnerable vendor software."
                ),
                revised_severity="low",
                is_false_positive=True,
            )
            ann = create_or_update_annotation(
                finding_id=finding.id,
                data=schema,
                expected_version=1,
                actor=actor,
                session=db_session,
            )
            db_session.commit()

            assert ann.version_id == 1
            assert ann.is_false_positive is True
            assert ann.revised_severity == "low"
            assert "Cloudflare" in ann.justification
            assert ann.author_id == user.id

            # Original finding and automated facts must remain unchanged (INV-03, INV-07)
            refreshed_finding = db_session.scalar(select(Finding).where(Finding.id == finding.id))
            assert refreshed_finding is not None
            assert refreshed_finding.severity == "high"
            assert refreshed_finding.rule_id == "SHODAN_CVE_OBSERVED"

    def test_update_annotation_increments_version(self, app: Flask, db_session: Session) -> None:
        _ws, _user, _assessment, finding, actor = _setup_annotation_environment(db_session)

        with app.app_context():
            # Initial create
            schema1 = AnnotationSchema(
                justification="Initial note.",
                revised_severity="medium",
                is_false_positive=False,
            )
            ann1 = create_or_update_annotation(
                finding_id=finding.id,
                data=schema1,
                expected_version=1,
                actor=actor,
                session=db_session,
            )
            db_session.commit()
            assert ann1.version_id == 1

            # Update with expected_version = 1
            schema2 = AnnotationSchema(
                justification="Updated note with verified vendor TPRM response.",
                revised_severity="low",
                is_false_positive=True,
            )
            ann2 = create_or_update_annotation(
                finding_id=finding.id,
                data=schema2,
                expected_version=1,
                actor=actor,
                session=db_session,
            )
            db_session.commit()

            # Version must be incremented to 2
            assert ann2.version_id == 2
            assert ann2.is_false_positive is True
            assert "TPRM response" in ann2.justification

    def test_optimistic_locking_conflict_raises_error(
        self, app: Flask, db_session: Session
    ) -> None:
        _ws, _user, _assessment, finding, actor = _setup_annotation_environment(db_session)

        with app.app_context():
            # First edit sets version to 1
            schema1 = AnnotationSchema(
                justification="Analyst A note.",
                revised_severity="medium",
                is_false_positive=False,
            )
            create_or_update_annotation(
                finding_id=finding.id,
                data=schema1,
                expected_version=1,
                actor=actor,
                session=db_session,
            )
            db_session.commit()

            # Second edit bumps version to 2
            schema2 = AnnotationSchema(
                justification="Analyst B note.",
                revised_severity="low",
                is_false_positive=False,
            )
            create_or_update_annotation(
                finding_id=finding.id,
                data=schema2,
                expected_version=1,
                actor=actor,
                session=db_session,
            )
            db_session.commit()

            # Analyst A tries to save with stale version 1 (which is now at 2)
            stale_schema = AnnotationSchema(
                justification="Stale edit from Analyst A.",
                revised_severity="informational",
                is_false_positive=True,
            )
            with pytest.raises(OptimisticLockConflictError) as exc_info:
                create_or_update_annotation(
                    finding_id=finding.id,
                    data=stale_schema,
                    expected_version=1,
                    actor=actor,
                    session=db_session,
                )
            assert exc_info.value.current_version == 2
            assert exc_info.value.expected_version == 1

    def test_annotation_http_endpoint_conflict_returns_409(
        self, app: Flask, client: FlaskClient, db_session: Session
    ) -> None:
        _ws, _user, assessment, finding, actor = _setup_annotation_environment(db_session)

        # 1. Successful first submission
        login_as(client, db_session, actor.user_id, actor.workspace_id)
        resp1 = client.post(
            f"/assessments/{assessment.id}/findings/{finding.id}/annotate",
            data={
                "version_id": "1",
                "justification": "First annotation entry",
                "revised_severity": "low",
                "is_false_positive": "true",
            },
        )
        assert resp1.status_code == 200
        html1 = resp1.get_data(as_text=True)
        assert "First annotation entry" in html1

        # 2. Concurrent submission with stale version_id returns 409
        login_as(client, db_session, actor.user_id, actor.workspace_id)
        resp_conflict = client.post(
            f"/assessments/{assessment.id}/findings/{finding.id}/annotate",
            data={
                "version_id": "99",
                "justification": "Conflict test",
                "revised_severity": "low",
            },
        )
        assert resp_conflict.status_code == 409
        html_conflict = resp_conflict.get_data(as_text=True)
        assert "Conflict (409)" in html_conflict
