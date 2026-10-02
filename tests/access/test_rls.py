"""Acceptance test suite ACC-02: PostgreSQL Row-Level Security (RLS) and connection isolation."""

import pytest
from flask import Flask
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import Membership, User, Workspace
from app.models.grant import AssessmentGrant
from app.service.access.context import ActorContext
from app.service.access.rls import set_transaction_actor


@pytest.fixture
def rls_seeded_db(app: Flask, db_session: Session) -> dict[str, object]:
    """Seed database with two workspaces, users, assessments, and grants with RLS enabled."""
    with app.app_context():
        # Workspace 1 & 2
        ws1 = Workspace(name="Workspace Alpha", enabled=True)
        ws2 = Workspace(name="Workspace Beta", enabled=True)
        db_session.add_all([ws1, ws2])
        db_session.flush()

        # Users
        u1 = User(email="alpha_owner@example.org", password="pwd", active=True)
        u2 = User(email="beta_owner@example.org", password="pwd", active=True)
        u_nogrant = User(email="alpha_guest@example.org", password="pwd", active=True)
        db_session.add_all([u1, u2, u_nogrant])
        db_session.flush()

        # Memberships
        db_session.add(Membership(workspace_id=ws1.id, user_id=u1.id, role="member", active=True))
        db_session.add(
            Membership(workspace_id=ws1.id, user_id=u_nogrant.id, role="member", active=True)
        )
        db_session.add(Membership(workspace_id=ws2.id, user_id=u2.id, role="member", active=True))
        db_session.flush()

        # Assessments
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

        # Grant on a1 to u1
        g1 = AssessmentGrant(
            workspace_id=ws1.id,
            assessment_id=a1.id,
            user_id=u1.id,
            role="owner",
            can_download=True,
            granted_by=u1.id,
        )
        # Grant on a2 to u2
        g2 = AssessmentGrant(
            workspace_id=ws2.id,
            assessment_id=a2.id,
            user_id=u2.id,
            role="owner",
            can_download=True,
            granted_by=u2.id,
        )
        db_session.add_all([g1, g2])
        db_session.commit()

        # Enable RLS policies on the test session connection and create non-superuser runtime role
        bind = db_session.get_bind()
        if bind.dialect.name == "postgresql":
            # Create runtime non-superuser role if not exists
            db_session.execute(
                text(
                    "DO $role_block$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
                    "rolname = 'web_runtime_test') THEN "
                    "CREATE ROLE web_runtime_test; "
                    "END IF; "
                    "END $role_block$;"
                )
            )
            db_session.execute(text("GRANT USAGE ON SCHEMA public TO web_runtime_test;"))
            db_session.execute(
                text("GRANT ALL ON ALL TABLES IN SCHEMA public TO web_runtime_test;")
            )
            db_session.execute(text("ALTER TABLE assessment ENABLE ROW LEVEL SECURITY;"))
            db_session.execute(text("ALTER TABLE assessment FORCE ROW LEVEL SECURITY;"))
            db_session.execute(
                text(
                    """
                    DROP POLICY IF EXISTS assessment_isolation_policy ON assessment;
                    CREATE POLICY assessment_isolation_policy ON assessment
                    FOR ALL
                    USING (
                        workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                        AND (
                            current_setting('app.is_admin', true) = 'true'
                            OR EXISTS (
                                SELECT 1 FROM assessment_grant ag
                                WHERE ag.assessment_id = assessment.id
                                  AND ag.user_id =
                                      NULLIF(current_setting('app.user_id', true), '')::uuid
                                  AND ag.revoked_at IS NULL
                                  AND (ag.expires_at IS NULL OR ag.expires_at > now())
                            )
                        )
                    );
                    """
                )
            )
            db_session.commit()

        actor_u1 = ActorContext.from_user(u1, ws1.id)
        actor_u2 = ActorContext.from_user(u2, ws2.id)
        actor_nogrant = ActorContext.from_user(u_nogrant, ws1.id)

        return {
            "ws1": ws1,
            "ws2": ws2,
            "a1": a1,
            "a2": a2,
            "actor_u1": actor_u1,
            "actor_u2": actor_u2,
            "actor_nogrant": actor_nogrant,
        }


def test_acc02_rls_direct_query_isolation(
    app: Flask, db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    """Verify that queries executed without actor context return 0 rows under RLS."""
    bind = db_session.get_bind()
    if bind.dialect.name != "postgresql":
        pytest.skip("RLS tests require PostgreSQL dialect")

    actor_u1 = rls_seeded_db["actor_u1"]
    assert isinstance(actor_u1, ActorContext)

    # Assume non-superuser runtime role to test RLS boundary enforcement
    db_session.execute(text("SET ROLE web_runtime_test;"))

    try:
        # 1. Without actor context -> 0 rows
        rows = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
        assert len(rows) == 0

        # 2. With actor_u1 context -> returns ONLY assessment a1
        with set_transaction_actor(db_session, actor_u1):
            rows_u1 = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
            assert len(rows_u1) == 1
            assert rows_u1[0].scope_ascii == "alpha.example.com"

        # 3. After exiting context manager -> session variables reset, returns 0 rows
        rows_after = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
        assert len(rows_after) == 0
    finally:
        db_session.execute(text("RESET ROLE;"))


def test_acc02_rls_pooled_connection_switch_isolation(
    app: Flask, db_session: Session, rls_seeded_db: dict[str, object]
) -> None:
    """Verify switching actor context across consecutive transactions on the same connection."""
    bind = db_session.get_bind()
    if bind.dialect.name != "postgresql":
        pytest.skip("RLS tests require PostgreSQL dialect")

    actor_u1 = rls_seeded_db["actor_u1"]
    actor_u2 = rls_seeded_db["actor_u2"]
    actor_nogrant = rls_seeded_db["actor_nogrant"]
    assert isinstance(actor_u1, ActorContext)
    assert isinstance(actor_u2, ActorContext)
    assert isinstance(actor_nogrant, ActorContext)

    db_session.execute(text("SET ROLE web_runtime_test;"))

    try:
        # Context 1: User 1 in Workspace 1
        with set_transaction_actor(db_session, actor_u1):
            rows1 = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
            assert len(rows1) == 1
            assert rows1[0].scope_ascii == "alpha.example.com"

        # Context 2: User 2 in Workspace 2 (on same DB connection)
        with set_transaction_actor(db_session, actor_u2):
            rows2 = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
            assert len(rows2) == 1
            assert rows2[0].scope_ascii == "beta.example.com"

        # Context 3: User in Workspace 1 with no grant
        with set_transaction_actor(db_session, actor_nogrant):
            rows3 = db_session.execute(text("SELECT id, scope_ascii FROM assessment")).fetchall()
            assert len(rows3) == 0
    finally:
        db_session.execute(text("RESET ROLE;"))
