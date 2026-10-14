"""The visibility ``team`` is called ``shared``.

An installation is one group of people: an assessment is private (its owner and the administrators)
or shared with everyone who can sign in. ``shared`` says that; ``team`` suggests a group that can be
chosen. The data and the check constraint change together, in one transaction. Audit entries keep
``{"visibility": "team"}`` as the history they are.

While an upgrade runs, code from before it still reads ``team``: the assessments that were shared
stay closed to colleagues until the new code is running, never open to more people.

Revision ID: 0005_visibility_shared
Revises: 0004_assessment_archive
Create Date: 2026-10-14
"""

from alembic import op

revision = "0005_visibility_shared"
down_revision = "0004_assessment_archive"
branch_labels = None
depends_on = None


def upgrade():
    # The constraint goes first: the update would break it, and the new one would break the old rows.
    op.drop_constraint("ck_assessment_visibility", "assessment", type_="check")
    op.execute("UPDATE assessment SET visibility = 'shared' WHERE visibility = 'team'")
    op.create_check_constraint(
        "ck_assessment_visibility", "assessment", "visibility IN ('private', 'shared')"
    )


def downgrade():
    op.drop_constraint("ck_assessment_visibility", "assessment", type_="check")
    op.execute("UPDATE assessment SET visibility = 'team' WHERE visibility = 'shared'")
    op.create_check_constraint(
        "ck_assessment_visibility", "assessment", "visibility IN ('private', 'team')"
    )
