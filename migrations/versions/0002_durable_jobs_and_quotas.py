"""Durable job queue, scan runs, and quota accounting tables with RLS.

Revision ID: 0002_durable_jobs_and_quotas
Revises: 0001_initial_schema_and_rls
Create Date: 2026-10-01 17:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_durable_jobs_and_quotas"
down_revision: str | None = "0001_initial_schema_and_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. ScanRun
    op.create_table(
        "scan_run",
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
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_key", sa.String(length=128), nullable=False),
        sa.Column("target_domain", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column(
            "revision",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "total_hosts_discovered",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancellation_reason", sa.String(length=512), nullable=True),
        sa.Column(
            "scope_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "redacted_config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "profile_version",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'1.0'"),
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
            "assessment_id",
            "request_key",
            name="uq_scan_run_assessment_request_key",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', "
            "'cancelled', 'failed', 'waiting_provider')",
            name="ck_scan_run_status",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_scan_run_revision_positive"),
        sa.CheckConstraint(
            "total_hosts_discovered >= 0",
            name="ck_scan_run_total_hosts_discovered_positive",
        ),
    )
    op.create_index("ix_scan_run_workspace_id", "scan_run", ["workspace_id"])
    op.create_index("ix_scan_run_assessment_id", "scan_run", ["assessment_id"])
    op.create_index("ix_scan_run_request_key", "scan_run", ["request_key"])
    op.create_index("ix_scan_run_status", "scan_run", ["status"])

    # 2. Job
    op.create_table(
        "job",
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
            nullable=True,
        ),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("logical_key", sa.String(length=255), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "priority",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("100"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3"),
        ),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "generation_id",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancel_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("result_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
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
        sa.UniqueConstraint("run_id", "logical_key", name="uq_job_run_logical_key"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', "
            "'cancelled', 'waiting_provider', 'skipped')",
            name="ck_job_status",
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_job_attempts_non_negative"),
        sa.CheckConstraint("max_attempts >= 1", name="ck_job_max_attempts_positive"),
        sa.CheckConstraint("generation_id >= 0", name="ck_job_generation_id_non_negative"),
    )
    op.create_index("ix_job_workspace_id", "job", ["workspace_id"])
    op.create_index("ix_job_assessment_id", "job", ["assessment_id"])
    op.create_index("ix_job_run_id", "job", ["run_id"])
    op.create_index("ix_job_job_type", "job", ["job_type"])
    op.create_index("ix_job_status", "job", ["status"])
    op.create_index("ix_job_lease_owner", "job", ["lease_owner"])
    op.create_index("ix_job_lease_expires_at", "job", ["lease_expires_at"])
    op.create_index("ix_job_available_at", "job", ["available_at"])
    op.create_index("ix_job_claimable", "job", ["status", "available_at", "priority", "created_at"])

    # 3. JobAttempt
    op.create_table(
        "job_attempt",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("job.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("generation_id", sa.Integer(), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'running'"),
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("worker_host", sa.String(length=128), nullable=True),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'failed', 'cancelled')",
            name="ck_job_attempt_status",
        ),
    )
    op.create_index("ix_job_attempt_job_id", "job_attempt", ["job_id"])

    # 4. ProviderQuota
    op.create_table(
        "provider_quota",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("period", sa.String(length=32), nullable=False),
        sa.Column("limit_amount", sa.Integer(), nullable=False),
        sa.Column("used_amount", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("reset_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.UniqueConstraint("workspace_id", "provider", "period", name="uq_provider_quota_window"),
        sa.CheckConstraint(
            "provider IN ('ct', 'shodan', 'webrisk', 'geoip')",
            name="ck_provider_quota_provider",
        ),
        sa.CheckConstraint(
            "period IN ('minute', 'hour', 'day', 'month')",
            name="ck_provider_quota_period",
        ),
        sa.CheckConstraint("limit_amount >= 0", name="ck_provider_quota_limit_non_negative"),
        sa.CheckConstraint("used_amount >= 0", name="ck_provider_quota_used_non_negative"),
    )
    op.create_index("ix_provider_quota_workspace_id", "provider_quota", ["workspace_id"])

    # 5. QuotaReservation
    op.create_table(
        "quota_reservation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("job.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'reserved'"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "provider IN ('ct', 'shodan', 'webrisk', 'geoip')",
            name="ck_quota_reservation_provider",
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'committed', 'released')",
            name="ck_quota_reservation_status",
        ),
        sa.CheckConstraint("amount > 0", name="ck_quota_reservation_amount_positive"),
    )
    op.create_index("ix_quota_reservation_workspace_id", "quota_reservation", ["workspace_id"])
    op.create_index("ix_quota_reservation_job_id", "quota_reservation", ["job_id"])
    op.create_index("ix_quota_reservation_status", "quota_reservation", ["status"])

    # Apply Row-Level Security (RLS) on PostgreSQL tables
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # 1. ScanRun RLS
        op.execute("ALTER TABLE scan_run ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE scan_run FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY scan_run_isolation_policy ON scan_run
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = scan_run.assessment_id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag.revoked_at IS NULL
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                    )
                )
            );
            """
        )

        # 2. Job RLS
        op.execute("ALTER TABLE job ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE job FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY job_isolation_policy ON job
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR EXISTS (
                        SELECT 1 FROM assessment_grant ag
                        WHERE ag.assessment_id = job.assessment_id
                          AND ag.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                          AND ag.revoked_at IS NULL
                          AND (ag.expires_at IS NULL OR ag.expires_at > now())
                    )
                )
            );
            """
        )

        # 3. JobAttempt RLS
        op.execute("ALTER TABLE job_attempt ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE job_attempt FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY job_attempt_isolation_policy ON job_attempt
            FOR ALL
            USING (
                EXISTS (
                    SELECT 1 FROM job j
                    WHERE j.id = job_attempt.job_id
                      AND j.workspace_id =
                          NULLIF(current_setting('app.workspace_id', true), '')::uuid
                      AND (
                          current_setting('app.is_admin', true) = 'true'
                          OR EXISTS (
                              SELECT 1 FROM assessment_grant ag
                              WHERE ag.assessment_id = j.assessment_id
                                AND ag.user_id =
                                    NULLIF(current_setting('app.user_id', true), '')::uuid
                                AND ag.revoked_at IS NULL
                                AND (ag.expires_at IS NULL OR ag.expires_at > now())
                          )
                      )
                )
            );
            """
        )

        # 4. ProviderQuota RLS
        op.execute("ALTER TABLE provider_quota ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE provider_quota FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY provider_quota_isolation_policy ON provider_quota
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR current_setting('app.user_id', true) IS NOT NULL
                )
            );
            """
        )

        # 5. QuotaReservation RLS
        op.execute("ALTER TABLE quota_reservation ENABLE ROW LEVEL SECURITY;")
        op.execute("ALTER TABLE quota_reservation FORCE ROW LEVEL SECURITY;")
        op.execute(
            """
            CREATE POLICY quota_reservation_isolation_policy ON quota_reservation
            FOR ALL
            USING (
                workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND (
                    current_setting('app.is_admin', true) = 'true'
                    OR current_setting('app.user_id', true) IS NOT NULL
                )
            );
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS quota_reservation_isolation_policy ON quota_reservation;")
        op.execute("DROP POLICY IF EXISTS provider_quota_isolation_policy ON provider_quota;")
        op.execute("DROP POLICY IF EXISTS job_attempt_isolation_policy ON job_attempt;")
        op.execute("DROP POLICY IF EXISTS job_isolation_policy ON job;")
        op.execute("DROP POLICY IF EXISTS scan_run_isolation_policy ON scan_run;")

    op.drop_table("quota_reservation")
    op.drop_table("provider_quota")
    op.drop_table("job_attempt")
    op.drop_table("job")
    op.drop_table("scan_run")
