"""The audit log: who did what, when, and to what.

``audit_event`` takes over from the ``app.audit`` logger lines of S2.6 (which a reopened finding
left as the only trace): sign-ins, assessments and their sharing, scans, exports, decisions about
findings and the accounts the administrators change. Rows are added in the transaction of the
change they record. The links to the user and the assessment are set to null when those are
deleted, so that the entry stays.

Revision ID: 0003_audit_event
Revises: 0002_manual_hosts
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_audit_event"
down_revision = "0002_manual_hosts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_event",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=48), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=True),
        sa.Column("subject", sa.String(length=255), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("remote_addr", sa.String(length=64), nullable=True),
        sa.CheckConstraint("source IN ('web', 'cli')", name="ck_audit_event_source"),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessment.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_event_occurred_at", "audit_event", ["occurred_at"])
    op.create_index(
        "ix_audit_event_assessment_id_occurred_at", "audit_event", ["assessment_id", "occurred_at"]
    )
    op.create_index("ix_audit_event_actor_id_occurred_at", "audit_event", ["actor_id", "occurred_at"])


def downgrade():
    op.drop_index("ix_audit_event_actor_id_occurred_at", table_name="audit_event")
    op.drop_index("ix_audit_event_assessment_id_occurred_at", table_name="audit_event")
    op.drop_index("ix_audit_event_occurred_at", table_name="audit_event")
    op.drop_table("audit_event")
