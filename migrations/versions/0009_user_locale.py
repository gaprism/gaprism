"""The language an account chose.

``user.locale`` is the code of one of the languages the installation offers (``de_CH``), or empty
for an account that never chose one: its pages then follow the language of the browser.

Revision ID: 0009_user_locale
Revises: 0008_user_picture
Create Date: 2026-11-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_user_locale"
down_revision = "0008_user_picture"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("locale", sa.String(length=10), nullable=True))


def downgrade():
    op.drop_column("user", "locale")
