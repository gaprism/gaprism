"""Who may see which assessment (decision D4: private by default, team toggle, admins see all)."""

from sqlalchemy.orm import Session

from app.service.assessments import can_access, is_admin, list_visible
from app.service.users import create_admin
from tests.helpers import create_assessment, create_user


def test_private_assessments_belong_to_their_owner_and_administrators(
    db_session: Session,
) -> None:
    owner = create_user(db_session)
    colleague = create_user(db_session)
    admin = create_admin(db_session, "admin@example.org", "Administrator-Pass-1")
    db_session.commit()
    private = create_assessment(db_session, owner, "private.example", "private")

    assert can_access(owner, private)
    assert can_access(admin, private)
    assert not can_access(colleague, private)


def test_team_assessments_are_open_to_every_signed_in_user(db_session: Session) -> None:
    owner = create_user(db_session)
    colleague = create_user(db_session)
    shared = create_assessment(db_session, owner, "shared.example", "team")

    assert can_access(colleague, shared)


def test_listing_matches_the_access_rules(db_session: Session) -> None:
    owner = create_user(db_session)
    colleague = create_user(db_session)
    admin = create_admin(db_session, "admin@example.org", "Administrator-Pass-1")
    db_session.commit()
    private = create_assessment(db_session, owner, "private.example", "private")
    shared = create_assessment(db_session, owner, "shared.example", "team")

    assert {a.id for a in list_visible(db_session, owner)} == {private.id, shared.id}
    assert {a.id for a in list_visible(db_session, colleague)} == {shared.id}
    assert {a.id for a in list_visible(db_session, admin)} == {private.id, shared.id}
    assert is_admin(admin) and not is_admin(owner)
