"""Persistent pseudonymous authentication rate-limit buckets.

Revision ID: 0006_auth_rate_limit
Revises: 0005_harden_rls_policies
Create Date: 2026-10-02 17:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_auth_rate_limit"
down_revision: str | None = "0005_harden_rls_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "auth_rate_limit_bucket",
        sa.Column("bucket_key", sa.String(length=64), primary_key=True),
        sa.Column("bucket_kind", sa.String(length=16), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "bucket_kind IN ('ip', 'principal')",
            name="ck_auth_bucket_kind",
        ),
        sa.CheckConstraint(
            "failures >= 0",
            name="ck_auth_bucket_failures_non_negative",
        ),
    )
    op.create_index(
        "ix_auth_rate_limit_blocked_until",
        "auth_rate_limit_bucket",
        ["blocked_until"],
    )
    op.create_index(
        "ix_auth_rate_limit_window_started_at",
        "auth_rate_limit_bucket",
        ["window_started_at"],
    )


def downgrade() -> None:
    op.drop_table("auth_rate_limit_bucket")
