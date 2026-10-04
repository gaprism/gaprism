"""ACC-02: PostgreSQL RLS and pooled connection isolation."""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from typing import cast

import pytest
from flask import Flask
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import Membership, User, Workspace
from app.models.check import CheckResult
from app.models.discovery import Host
from app.models.grant import AssessmentGrant
from app.models.scan_run import ScanRun
from app.service.access.context import ActorContext
from app.service.access.rls import set_transaction_actor

RUNTIME_ROLE = "web_runtime_test"
RLS_FUNCTIONS = (
    "public.app_has_workspace_membership(uuid)",
    "public.app_is_workspace_admin(uuid)",
    "public.app_has_assessment_role(uuid,uuid,text[])",
    "public.app_has_report_version_access(uuid,uuid)",
    "public.app_can_manage_assessment_grant(uuid,uuid,uuid)",
    "public.app_can_manage_report_grant(uuid,uuid,uuid)",
    "public.app_has_job_role(uuid,text[])",
)


def _runtime_role_on(session: Session) -> None:
    session.execute(text(f"SET ROLE {RUNTIME_ROLE}"))


def _runtime_role_off(session: Session) -> None:
    session.rollback()
    session.execute(text("RESET ROLE"))
    session.commit()


@pytest.fixture
def rls_seeded_db(app: Flask, db_session: Session) -> Iterator[dict[str, object]]:
    """Seed two workspaces and expose only least-privilege reads to a runtime role."""
    with app.app_context():
        if db_session.get_bind().dialect.name != "postgresql":
            pytest.skip("RLS tests require PostgreSQL")

        ws1 = Workspace(name="Workspace Alpha", enabled=True)
        ws2 = Workspace(name="Workspace Beta", enabled=True)
        db_session.add_all([ws1, ws2])
        db_session.flush()

        u1 = User(email="alpha_owner@example.org", password="pwd", active=True)
        u2 = User(email="beta_owner@example.org", password="pwd", active=True)
        viewer = User(email="alpha_viewer@example.org", password="pwd", active=True)
        admin = User(email="alpha_admin@example.org", password="pwd", active=True)
        db_session.add_all([u1, u2, viewer, admin])
        db_session.flush()

        db_session.add_all(
            [
                Membership(workspace_id=ws1.id, user_id=u1.id, role="member", active=True),
                Membership(
                    workspace_id=ws1.id,
                    user_id=viewer.id,
                    role="member",
                    active=True,
                ),
                Membership(
                    workspace_id=ws1.id,
                    user_id=admin.id,
                    role="admin",
                    active=True,
                ),
                Membership(workspace_id=ws2.id, user_id=u2.id, role="member", active=True),
            ]
        )
        db_session.flush()

        a1 = Assessment(
            workspace_id=ws1.id,
            supplier_label="Alpha Target",
            scope_ascii="alpha.example.com",
            scope_display="alpha.example.com",
            created_by=u1.id,
            owner_user_id=u1.id,
            state="active",
        )
        a2 = Assessment(
            workspace_id=ws2.id,
            supplier_label="Beta Target",
            scope_ascii="beta.example.com",
            scope_display="beta.example.com",
            created_by=u2.id,
            owner_user_id=u2.id,
            state="active",
        )
        db_session.add_all([a1, a2])
        db_session.flush()

        db_session.add_all(
            [
                AssessmentGrant(
                    workspace_id=ws1.id,
                    assessment_id=a1.id,
                    user_id=u1.id,
                    role="owner",
                    can_download=True,
                    granted_by=u1.id,
                ),
                AssessmentGrant(
                    workspace_id=ws1.id,
                    assessment_id=a1.id,
                    user_id=viewer.id,
                    role="viewer",
                    can_download=False,
                    granted_by=u1.id,
                ),
                AssessmentGrant(
                    workspace_id=ws2.id,
                    assessment_id=a2.id,
                    user_id=u2.id,
                    role="owner",
                    can_download=True,
                    granted_by=u2.id,
                ),
            ]
        )

        run1 = ScanRun(
            workspace_id=ws1.id,
            assessment_id=a1.id,
            requested_by=u1.id,
            request_key="alpha-run",
            target_domain="alpha.example.com",
            status="completed",
        )
        run2 = ScanRun(
            workspace_id=ws2.id,
            assessment_id=a2.id,
            requested_by=u2.id,
            request_key="beta-run",
            target_domain="beta.example.com",
            status="completed",
        )
        db_session.add_all([run1, run2])
        db_session.flush()

        host1 = Host(
            workspace_id=ws1.id,
            assessment_id=a1.id,
            name_ascii="www.alpha.example.com",
            name_display="www.alpha.example.com",
        )
        host2 = Host(
            workspace_id=ws2.id,
            assessment_id=a2.id,
            name_ascii="www.beta.example.com",
            name_display="www.beta.example.com",
        )
        db_session.add_all([host1, host2])
        db_session.flush()
        db_session.add_all(
            [
                CheckResult(
                    workspace_id=ws1.id,
                    assessment_id=a1.id,
                    run_id=run1.id,
                    host_id=host1.id,
                    logical_check_key="alpha:tls",
                    subject_kind="hostname",
                    check_type="tls",
                    status="succeeded",
                    payload={},
                ),
                CheckResult(
                    workspace_id=ws2.id,
                    assessment_id=a2.id,
                    run_id=run2.id,
                    host_id=host2.id,
                    logical_check_key="beta:tls",
                    subject_kind="hostname",
                    check_type="tls",
                    status="succeeded",
                    payload={},
                ),
            ]
        )
        db_session.commit()

        db_session.execute(
            text(
                "DO $role$ BEGIN "
                f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN "
                f"CREATE ROLE {RUNTIME_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS; "
                "END IF; END $role$"
            )
        )
        db_session.execute(text(f"ALTER ROLE {RUNTIME_ROLE} NOSUPERUSER NOBYPASSRLS NOINHERIT"))
        db_session.execute(text(f"GRANT USAGE ON SCHEMA public TO {RUNTIME_ROLE}"))
        db_session.execute(
            text(
                f"GRANT SELECT ON assessment, assessment_grant, host, check_result "
                f"TO {RUNTIME_ROLE}"
            )
        )
        for function_name in RLS_FUNCTIONS:
            db_session.execute(text(f"GRANT EXECUTE ON FUNCTION {function_name} TO {RUNTIME_ROLE}"))
        db_session.commit()

        result = {
            "a1_id": a1.id,
            "actor_u1": ActorContext.from_user(u1, ws1.id),
            "actor_u2": ActorContext.from_user(u2, ws2.id),
            "actor_viewer": ActorContext.from_user(viewer, ws1.id),
            "actor_admin": ActorContext.from_user(admin, ws1.id),
        }
        try:
            yield result
        finally:
            _runtime_role_off(db_session)


def test_acc02_missing_context_and_admin_without_grant_are_denied(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    actor_admin = rls_seeded_db["actor_admin"]
    assert isinstance(actor_admin, ActorContext)
    assert actor_admin.is_admin
    _runtime_role_on(db_session)

    assert db_session.execute(text("SELECT count(*) FROM assessment")).scalar_one() == 0
    with set_transaction_actor(db_session, actor_admin):
        assert db_session.execute(text("SELECT count(*) FROM assessment")).scalar_one() == 0
        assert db_session.execute(text("SELECT count(*) FROM host")).scalar_one() == 0
        assert db_session.execute(text("SELECT count(*) FROM check_result")).scalar_one() == 0


def test_acc02_case_and_child_rows_are_isolated(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    actor_u1 = rls_seeded_db["actor_u1"]
    assert isinstance(actor_u1, ActorContext)
    _runtime_role_on(db_session)

    with set_transaction_actor(db_session, actor_u1):
        scopes = list(
            cast(
                Sequence[str],
                db_session.execute(text("SELECT scope_ascii FROM assessment")).scalars().all(),
            )
        )
        hosts = list(
            cast(
                Sequence[str],
                db_session.execute(text("SELECT name_ascii FROM host")).scalars().all(),
            )
        )
        checks = list(
            cast(
                Sequence[str],
                db_session.execute(text("SELECT logical_check_key FROM check_result"))
                .scalars()
                .all(),
            )
        )

    assert scopes == ["alpha.example.com"]
    assert hosts == ["www.alpha.example.com"]
    assert checks == ["alpha:tls"]
    assert db_session.execute(text("SELECT count(*) FROM assessment")).scalar_one() == 0


def test_acc02_grant_visibility_does_not_recurse(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    actor_u1 = rls_seeded_db["actor_u1"]
    actor_viewer = rls_seeded_db["actor_viewer"]
    assert isinstance(actor_u1, ActorContext)
    assert isinstance(actor_viewer, ActorContext)
    _runtime_role_on(db_session)

    with set_transaction_actor(db_session, actor_u1):
        assert db_session.execute(text("SELECT count(*) FROM assessment_grant")).scalar_one() == 2
    with set_transaction_actor(db_session, actor_viewer):
        grants = list(
            cast(
                Sequence[str],
                db_session.execute(text("SELECT role FROM assessment_grant ORDER BY role"))
                .scalars()
                .all(),
            )
        )
        assert grants == ["viewer"]


def test_acc02_pooled_connection_switch_clears_context(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    actor_u1 = rls_seeded_db["actor_u1"]
    actor_u2 = rls_seeded_db["actor_u2"]
    assert isinstance(actor_u1, ActorContext)
    assert isinstance(actor_u2, ActorContext)
    _runtime_role_on(db_session)

    with set_transaction_actor(db_session, actor_u1):
        assert db_session.execute(text("SELECT scope_ascii FROM assessment")).scalar_one() == (
            "alpha.example.com"
        )
    with set_transaction_actor(db_session, actor_u2):
        assert db_session.execute(text("SELECT scope_ascii FROM assessment")).scalar_one() == (
            "beta.example.com"
        )
    assert db_session.execute(text("SELECT count(*) FROM assessment")).scalar_one() == 0


def test_acc02_runtime_role_cannot_bypass_or_alter_rls(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    properties = db_session.execute(
        text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :role"),
        {"role": RUNTIME_ROLE},
    ).one()
    assert properties == (False, False)

    _runtime_role_on(db_session)
    savepoint = db_session.begin_nested()
    try:
        with pytest.raises(DBAPIError):
            db_session.execute(text("ALTER TABLE assessment DISABLE ROW LEVEL SECURITY"))
    finally:
        savepoint.rollback()


def test_transaction_context_restores_nested_actor(
    db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    actor_u1 = rls_seeded_db["actor_u1"]
    actor_u2 = rls_seeded_db["actor_u2"]
    assert isinstance(actor_u1, ActorContext)
    assert isinstance(actor_u2, ActorContext)
    _runtime_role_on(db_session)

    with set_transaction_actor(db_session, actor_u1):
        with set_transaction_actor(db_session, actor_u2):
            assert db_session.execute(text("SELECT scope_ascii FROM assessment")).scalar_one() == (
                "beta.example.com"
            )
        assert db_session.execute(text("SELECT scope_ascii FROM assessment")).scalar_one() == (
            "alpha.example.com"
        )


def test_fixture_ids_are_uuid_values(rls_seeded_db: dict[str, object]) -> None:
    """Keep seed output detached from privileged ORM lazy loading during RLS tests."""
    assert isinstance(rls_seeded_db["a1_id"], uuid.UUID)
