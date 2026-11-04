"""An optional name for each account.

``user.name`` is what a person calls themselves on their profile page: free text of up to 100
characters, empty for the accounts that never set one (the interface then shows the e-mail address).

Revision ID: 0007_user_name
Revises: 0006_user_invitation
Create Date: 2026-11-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_user_name"
down_revision = "0006_user_invitation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("name", sa.String(length=100), nullable=True))


def downgrade():
    op.drop_column("user", "name")
