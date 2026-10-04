"""Checks, findings, and annotations tables with RLS and host lookup index.

Revision ID: 0004_checks_findings_annotations
Revises: 0003_discovery_and_observations
Create Date: 2026-10-02 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_checks_findings_annotations"
down_revision: str | None = "0003_discovery_and_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 0. Additional composite index on Host for fast assessment lookup (PERF-01)
    op.create_index(
        "idx_host_assessment_lookup",
        "host",
        ["assessment_id", "name_ascii"],
    )

    # 1. CheckResult
    op.create_table(
        "check_result",
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
            nullable=True,
        ),
        sa.Column("logical_check_key", sa.String(length=255), nullable=False),
        sa.Column("subject_kind", sa.String(length=32), nullable=False),
        sa.Column("check_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=64), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("adapter_version", sa.String(length=64), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("attribution", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=True),
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
        sa.UniqueConstraint("run_id", "logical_check_key", name="uq_check_result_run_key"),
        sa.CheckConstraint(
            "status IN ('succeeded', 'failed', 'skipped')",
            name="ck_check_result_status",
        ),
        sa.CheckConstraint(
            "subject_kind IN ('hostname', 'endpoint', 'ip', 'url')",
            name="ck_check_result_subject_kind",
        ),
    )
    op.create_index("ix_check_result_workspace_id", "check_result", ["workspace_id"])
    op.create_index("ix_check_result_assessment_id", "check_result", ["assessment_id"])
    op.create_index("ix_check_result_run_id", "check_result", ["run_id"])
    op.create_index("ix_check_result_host_id", "check_result", ["host_id"])
    op.create_index("ix_check_result_check_type", "check_result", ["check_type"])

    # 2. Finding
    op.create_table(
        "finding",
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
            nullable=True,
        ),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("subject_key", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("attribution", sa.String(length=64), nullable=False),
        sa.Column("message_key", sa.String(length=128), nullable=False),
        sa.Column(
            "message_parameters",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
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
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_finding_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('low', 'medium', 'high', 'unknown')",
            name="ck_finding_confidence",
        ),
        sa.CheckConstraint(
            "attribution IN ('hostname_supported', 'ip_only', 'shared_infrastructure', 'unknown')",
            name="ck_finding_attribution",
        ),
    )
    op.create_index("ix_finding_workspace_id", "finding", ["workspace_id"])
    op.create_index("ix_finding_assessment_id", "finding", ["assessment_id"])
    op.create_index("ix_finding_run_id", "finding", ["run_id"])
    op.create_index("ix_finding_host_id", "finding", ["host_id"])
    op.create_index("ix_finding_severity", "finding", ["severity"])

    # 3. FindingAnnotation
    op.create_table(
        "finding_annotation",
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
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("finding.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("revised_severity", sa.String(length=32), nullable=True),
        sa.Column(
            "is_false_positive",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("version_id", sa.Integer(), nullable=False, server_default=sa.text("1")),
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
            "revised_severity IS NULL OR revised_severity IN "
            "('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_annotation_revised_severity",
        ),
        sa.CheckConstraint("version_id >= 1", name="ck_annotation_version_positive"),
    )
    op.create_index("ix_finding_annotation_workspace_id", "finding_annotation", ["workspace_id"])
    op.create_index("ix_finding_annotation_assessment_id", "finding_annotation", ["assessment_id"])
    op.create_index("ix_finding_annotation_finding_id", "finding_annotation", ["finding_id"])
    op.create_index("ix_finding_annotation_author_id", "finding_annotation", ["author_id"])

    # 4. PostgreSQL RLS configuration for new tables
    tables = [
        "check_result",
        "finding",
        "finding_annotation",
    ]

    for table in tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL
                USING (
                    workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                    AND (
                        NULLIF(current_setting('app.is_admin', true), '')::boolean = true
                        OR assessment_id IN (
                            SELECT assessment_id FROM assessment_grant
                            WHERE user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                            AND (expires_at IS NULL OR expires_at > now())
                            AND revoked_at IS NULL
                        )
                    )
                );
            """
        )


def downgrade() -> None:
    tables = [
        "finding_annotation",
        "finding",
        "check_result",
    ]

    for table in tables:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};")
        op.drop_table(table)

    op.drop_index("idx_host_assessment_lookup", table_name="host")
