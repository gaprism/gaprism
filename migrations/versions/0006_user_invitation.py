"""One-time links for new and existing accounts.

``user_invitation`` holds at most one link per account and purpose: an invitation for a new
account, a reset for an existing one. Only the SHA-256 of a link is stored, never the link. The row
is deleted when the link is used, so an account that still has an ``invite`` row has not accepted
its invitation yet. The rows go with their account; the account that made a link is set to null
when it is deleted, so that the row stays valid.

Revision ID: 0006_user_invitation
Revises: 0005_visibility_shared
Create Date: 2026-10-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_user_invitation"
down_revision = "0005_visibility_shared"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_invitation",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("purpose", sa.String(length=8), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("reset_authenticator", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.CheckConstraint("purpose IN ('invite', 'reset')", name="ck_user_invitation_purpose"),
        sa.ForeignKeyConstraint(["created_by"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "purpose", name="uq_user_invitation_user_purpose"),
    )
    op.create_index("ix_user_invitation_token_hash", "user_invitation", ["token_hash"], unique=True)


def downgrade():
    op.drop_index("ix_user_invitation_token_hash", table_name="user_invitation")
    op.drop_table("user_invitation")
