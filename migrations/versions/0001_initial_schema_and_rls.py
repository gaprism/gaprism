"""Initial database schema and Row-Level Security (RLS) policies.

Revision ID: 0001_initial_schema_and_rls
Revises:
Create Date: 2026-10-01 16:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema_and_rls"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Workspace
    op.create_table(
        "workspace",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # 2. Role
    op.create_table(
        "role",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=80), unique=True, nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("permissions", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_role_name", "role", ["name"], unique=True)

    # 3. User
    op.create_table(
        "user",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=255), unique=True, nullable=False),
        sa.Column("password", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("fs_uniquifier", sa.String(length=64), unique=True, nullable=False),
        sa.Column("fs_webauthn_user_handle", sa.String(length=64), unique=True, nullable=True),
        sa.Column("tf_primary_method", sa.String(length=64), nullable=True),
        sa.Column("tf_totp_secret", sa.String(length=255), nullable=True),
        sa.Column(
            "create_datetime",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "update_datetime",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("current_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_login_ip", sa.String(length=64), nullable=True),
        sa.Column("last_login_ip", sa.String(length=64), nullable=True),
        sa.Column("login_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)
    op.create_index("ix_user_fs_uniquifier", "user", ["fs_uniquifier"], unique=True)

    # 4. UserRoles
    op.create_table(
        "user_roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("role.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint("user_id", "role_id", name="uq_user_roles_user_role"),
    )
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"])
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"])

    # 5. Membership
    op.create_table(
        "membership",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="member"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_membership_workspace_user"),
        sa.CheckConstraint("role IN ('admin', 'member')", name="ck_membership_role_valid"),
    )
    op.create_index("ix_membership_workspace_id", "membership", ["workspace_id"])
    op.create_index("ix_membership_user_id", "membership", ["user_id"])

    # 6. Assessment
    op.create_table(
        "assessment",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("supplier_label", sa.String(length=255), nullable=False),
        sa.Column("scope_ascii", sa.String(length=255), nullable=False),
        sa.Column("scope_display", sa.String(length=255), nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "owner_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("state IN ('active', 'archived')", name="ck_assessment_state"),
        sa.CheckConstraint("revision >= 1", name="ck_assessment_revision_positive"),
    )
    op.create_index("ix_assessment_workspace_id", "assessment", ["workspace_id"])
    op.create_index("ix_assessment_scope_ascii", "assessment", ["scope_ascii"])
    op.create_index("ix_assessment_owner_user_id", "assessment", ["owner_user_id"])

    # 7. AssessmentGrant
    op.create_table(
        "assessment_grant",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("can_download", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "granted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "assessment_id", "user_id", name="uq_assessment_grant_assessment_user"
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'analyst', 'reviewer', 'viewer')",
            name="ck_assessment_grant_role",
        ),
    )
    op.create_index("ix_assessment_grant_workspace_id", "assessment_grant", ["workspace_id"])
    op.create_index("ix_assessment_grant_assessment_id", "assessment_grant", ["assessment_id"])
    op.create_index("ix_assessment_grant_user_id", "assessment_grant", ["user_id"])

    # 8. Report
    op.create_table(
        "report",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_report_workspace_id", "report", ["workspace_id"])
    op.create_index("ix_report_assessment_id", "report", ["assessment_id"])

    # 9. ReportVersion
    op.create_table(
        "report_version",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("report.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("source_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("snapshot_schema", sa.String(length=64), nullable=False, server_default="1.0"),
        sa.Column("snapshot_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="preparing"),
        sa.Column(
            "preparer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=64), nullable=False, server_default="1.0"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("report_id", "version_number", name="uq_report_version_report_number"),
        sa.CheckConstraint(
            "state IN ('preparing', 'draft', 'issuing', 'issued')",
            name="ck_report_version_state",
        ),
        sa.CheckConstraint("version_number >= 1", name="ck_report_version_number_positive"),
    )
    op.create_index("ix_report_version_workspace_id", "report_version", ["workspace_id"])
    op.create_index("ix_report_version_report_id", "report_version", ["report_id"])
    op.create_index("ix_report_version_assessment_id", "report_version", ["assessment_id"])

    # 10. ReportGrant
    op.create_table(
        "report_grant",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "report_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("report_version.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("can_download", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "granted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "report_version_id", "user_id", name="uq_report_grant_version_user"
        ),
    )
    op.create_index("ix_report_grant_workspace_id", "report_grant", ["workspace_id"])
    op.create_index("ix_report_grant_report_version_id", "report_grant", ["report_version_id"])
    op.create_index("ix_report_grant_user_id", "report_grant", ["user_id"])

    # Apply Row-Level Security (RLS) on PostgreSQL tables
    # Note: RLS policies are applied only when on postgresql dialect
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # 1. Assessment RLS
        op.execute("ALTER TABLE assessment ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE assessment FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY assessment_isolation_policy ON assessment
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = assessment.id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag.revoked_at IS NULL
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                    )
                )
            );
            """
        )

        # 2. AssessmentGrant RLS
        op.execute("ALTER TABLE assessment_grant ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE assessment_grant FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY assessment_grant_isolation_policy ON assessment_grant
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                    OR current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag_owner
                        WHERE ag_owner.assessment_id = assessment_grant.assessment_id
                          AND ag_owner.user_id =
                              NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag_owner.role = 'owner'
                          AND ag_owner.revoked_at IS NULL
                          AND (ag_owner.expires_at IS NULL OR ag_owner.expires_at > now())
                    )
                )
            );
            """
        )

        # 3. Report RLS
        op.execute("ALTER TABLE report ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE report FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY report_isolation_policy ON report
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = report.assessment_id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag.revoked_at IS NULL
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                    )
                )
            );
            """
        )

        # 4. ReportVersion RLS
        op.execute("ALTER TABLE report_version ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE report_version FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY report_version_isolation_policy ON report_version
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = report_version.assessment_id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag.revoked_at IS NULL
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                    )
                    OR (
                        report_version.state = 'issued'
                        AND EXISTS (
                            SELECT 1 FROM report_grant rg
                            WHERE rg.report_version_id = report_version.id
                              AND rg.user_id =
                                  NULLIF(current_setting('app.user_id', true), '')::uuid
                              AND rg.revoked_at IS NULL
                              AND (rg.expires_at IS NULL OR rg.expires_at > now())
                        )
                    )
                )
            );
            """
        )

        # 5. ReportGrant RLS
        op.execute("ALTER TABLE report_grant ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE report_grant FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY report_grant_isolation_policy ON report_grant
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                    OR current_setting('app.is_admin', true) = 'true'
                )
            );
            """
        )

        # 6. Membership RLS
        op.execute("ALTER TABLE membership ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE membership FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY membership_isolation_policy ON membership
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                    OR current_setting('app.is_admin', true) = 'true'
                )
            );
            """
        )

        # 7. Workspace RLS
        op.execute("ALTER TABLE workspace ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE workspace FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY workspace_isolation_policy ON workspace
            FOR ALL
            USING (
                id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
            );
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS workspace_isolation_policy ON workspace;")
        op.execute("DROP POLICY IF EXISTS membership_isolation_policy ON membership;")
        op.execute("DROP POLICY IF EXISTS report_grant_isolation_policy ON report_grant;")
        op.execute("DROP POLICY IF EXISTS report_version_isolation_policy ON report_version;")
        op.execute("DROP POLICY IF EXISTS report_isolation_policy ON report;")
        op.execute("DROP POLICY IF EXISTS assessment_grant_isolation_policy ON assessment_grant;")
        op.execute("DROP POLICY IF EXISTS assessment_isolation_policy ON assessment;")

    op.drop_table("report_grant")
    op.drop_table("report_version")
    op.drop_table("report")
    op.drop_table("assessment_grant")
    op.drop_table("assessment")
    op.drop_table("membership")
    op.drop_table("user_roles")
    op.drop_table("user")
    op.drop_table("role")
    op.drop_table("workspace")
