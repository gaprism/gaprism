"""Manual hosts per assessment, and at most one active scan per assessment.

- ``assessment.manual_hosts``: hostnames an analyst adds by hand (the escape hatch when CT is
  down); they join every later scan.
- ``uq_scan_active_per_assessment``: the database refuses a second queued/running scan for the
  same assessment, so two simultaneous "start scan" requests cannot both succeed.

Revision ID: 0002_manual_hosts
Revises: 0001_baseline
Create Date: 2026-10-04
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_manual_hosts"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "assessment",
        sa.Column(
            "manual_hosts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.create_index(
        "uq_scan_active_per_assessment",
        "scan",
        ["assessment_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade():
    op.drop_index(
        "uq_scan_active_per_assessment",
        table_name="scan",
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.drop_column("assessment", "manual_hosts")
