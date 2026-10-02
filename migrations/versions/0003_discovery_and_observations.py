"""Discovery and observation tables: host, run_host, ct_name_observation with RLS.

Revision ID: 0003_discovery_and_observations
Revises: 0002_durable_jobs_and_quotas
Create Date: 2026-10-02 08:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003_discovery_and_observations"
down_revision: str | None = "0002_durable_jobs_and_quotas"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Host
    op.create_table(
        "host",
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
        sa.Column("name_ascii", sa.String(length=255), nullable=False),
        sa.Column("name_display", sa.String(length=255), nullable=False),
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
        sa.UniqueConstraint("assessment_id", "name_ascii", name="uq_host_assessment_name_ascii"),
    )
    op.create_index("ix_host_workspace_id", "host", ["workspace_id"])
    op.create_index("ix_host_assessment_id", "host", ["assessment_id"])
    op.create_index("ix_host_name_ascii", "host", ["name_ascii"])

    # 2. RunHost
    op.create_table(
        "run_host",
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
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("host.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "discovery_source",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'ct_log'"),
        ),
        sa.Column(
            "eligibility",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'eligible'"),
        ),
        sa.Column("exclusion_reason", sa.String(length=255), nullable=True),
        sa.Column("first_collected_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("run_id", "host_id", name="uq_run_host_run_host_id"),
        sa.CheckConstraint(
            "eligibility IN ('eligible', 'ineligible', 'excluded')",
            name="ck_run_host_eligibility",
        ),
    )
    op.create_index("ix_run_host_workspace_id", "run_host", ["workspace_id"])
    op.create_index("ix_run_host_assessment_id", "run_host", ["assessment_id"])
    op.create_index("ix_run_host_run_id", "run_host", ["run_id"])
    op.create_index("ix_run_host_host_id", "run_host", ["host_id"])

    # 3. CTNameObservation
    op.create_table(
        "ct_name_observation",
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
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name_pattern", sa.String(length=255), nullable=False),
        sa.Column("is_wildcard", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("entry_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.UniqueConstraint("run_id", "name_pattern", name="uq_ct_obs_run_name_pattern"),
        sa.CheckConstraint("entry_count >= 0", name="ck_ct_obs_entry_count_non_negative"),
    )
    op.create_index(
        "ix_ct_name_observation_workspace_id", "ct_name_observation", ["workspace_id"]
    )
    op.create_index(
        "ix_ct_name_observation_assessment_id", "ct_name_observation", ["assessment_id"]
    )
    op.create_index("ix_ct_name_observation_run_id", "ct_name_observation", ["run_id"])

    # Apply Row-Level Security
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ["host", "run_host", "ct_name_observation"]:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

            op.execute(
                f"""
                CREATE POLICY {table}_workspace_isolation_policy ON {table}
                AS RESTRICTIVE
                USING (
                    workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                );
                """
            )

            op.execute(
                f"""
                CREATE POLICY {table}_assessment_access_policy ON {table}
                AS RESTRICTIVE
                USING (
                    EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = {table}.assessment_id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                          AND ag.revoked_at IS NULL
                    )
                );
                """
            )


def downgrade() -> None:
    op.drop_table("ct_name_observation")
    op.drop_table("run_host")
    op.drop_table("host")
