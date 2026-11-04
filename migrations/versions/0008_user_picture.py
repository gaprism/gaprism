"""A picture for each account.

``user_image`` holds at most one picture per account (a small square WebP that the application
made of the upload, never the upload) and goes with its account. ``user.picture_version`` is empty
for an account without a picture and otherwise names the stored one (the start of its SHA-256), so
that a page knows whether to ask for a picture without reading the table, and a browser can keep
one for as long as the name stays the same.

Revision ID: 0008_user_picture
Revises: 0007_user_name
Create Date: 2026-11-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_user_picture"
down_revision = "0007_user_name"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("picture_version", sa.String(length=16), nullable=True))
    op.create_table(
        "user_image",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="uq_user_image_user_id"),
    )


def downgrade():
    op.drop_table("user_image")
    op.drop_column("user", "picture_version")
