"""Archiving an assessment: hidden from the default list and read-only.

``assessment.archived_at`` is null for a live assessment and holds the time it was archived
otherwise. Deleting an assessment needs no change: the foreign keys of scans, hosts, check results,
findings and decisions already cascade, and the audit entries keep their text when the link to the
assessment is cleared.

Revision ID: 0004_assessment_archive
Revises: 0003_audit_event
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_assessment_archive"
down_revision = "0003_audit_event"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "assessment", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade():
    op.drop_column("assessment", "archived_at")
