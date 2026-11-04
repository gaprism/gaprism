"""The accounts of the team: creating, switching off, roles, passwords and lost authenticators."""

from __future__ import annotations

import logging

import pytest
from flask.testing import FlaskClient
from flask_security.utils import verify_password
from sqlalchemy.orm import Session

from app.extensions import security
from app.models.auth import User
from app.service import users as user_service
from app.service.users import AccountExistsError, UserAdminError
from tests.helpers import audit_rows, login_as

PASSWORD = "Correct-Horse-Battery-1"
ACCENTED = "Grüezi-mitenand-2026"  # the u-umlaut as the one character a Swiss keyboard types
# What the last active administrator is told: what happened, what to do, and why an invitation does
# not help yet. Whole sentences, one for each change: nothing is filled in afterwards.
SWITCH_OFF_REFUSAL = (
    "This account is the last active administrator, so it cannot be switched off. "
    "Make another account an administrator first. "
    "A person who was invited counts once they have set a password."
)
ROLE_REFUSAL = (
    "This account is the last active administrator, so it cannot lose the administrator role. "
    "Make another account an administrator first. "
    "A person who was invited counts once they have set a password."
)


def member(session: Session, email: str = "member@example.org") -> User:
    user = user_service.create_user(session, email, PASSWORD)
    session.commit()
    return user


def admin(session: Session, email: str = "boss@example.org") -> User:
    user = user_service.create_user(session, email, PASSWORD, admin=True)
    session.commit()
    return user


# ------------------------------------------------------------------------------ creating


def test_an_account_records_how_it_came_about_when_it_is_told(db_session: Session) -> None:
    user_service.create_user(db_session, "plain@example.org", PASSWORD)
    user_service.create_user(db_session, "link@example.org", PASSWORD, via="invitation")
    plain, linked = audit_rows(db_session, "user.created")
    assert "via" not in plain.details and linked.details["via"] == "invitation"


def test_signing_an_account_out_everywhere_changes_its_session_identifier(
    db_session: Session,
) -> None:
    user = member(db_session)
    before = user.fs_uniquifier
    assert user_service.sign_out_everywhere(db_session, user.email) is user
    assert user.fs_uniquifier != before
    (event,) = audit_rows(db_session, "user.sessions_ended")
    assert event.subject == str(user.id)

    with pytest.raises(UserAdminError, match="no account"):
        user_service.sign_out_everywhere(db_session, "nobody@example.org")


def test_a_member_is_created_active_with_a_hashed_password(db_session: Session) -> None:
    user = user_service.create_user(db_session, "  New.Member@Example.org ", PASSWORD)
    assert user.email == "new.member@example.org" and user.active
    assert user.password != PASSWORD and verify_password(PASSWORD, user.password)
    assert not user_service.holds_admin_role(user)


def test_an_administrator_has_the_role(db_session: Session) -> None:
    assert user_service.holds_admin_role(
        user_service.create_user(db_session, "a@example.org", PASSWORD, admin=True)
    )


@pytest.mark.parametrize(
    ("email", "password", "message"),
    [
        ("not-an-address", PASSWORD, "valid e-mail address"),
        ("x@example.org", "short", "at least 12 characters"),
    ],
)
def test_a_bad_address_or_a_short_password_creates_nothing(
    db_session: Session, email: str, password: str, message: str
) -> None:
    with pytest.raises(UserAdminError, match=message):
        user_service.create_user(db_session, email, password)
    assert db_session.query(User).count() == 0


def test_an_address_can_have_one_account_only(db_session: Session) -> None:
    member(db_session)
    with pytest.raises(AccountExistsError, match="exists already"):
        user_service.create_user(db_session, "MEMBER@example.org", PASSWORD)


def test_a_refusal_keeps_its_text_apart_from_what_fills_it(db_session: Session) -> None:
    """The screens translate the text first and fill it in after (``_(e.message, **e.params)``);
    the command line prints the English sentence."""
    with pytest.raises(UserAdminError) as short:
        user_service.check_password("short")
    assert short.value.message == "The password is too short. Use at least %(length)s characters."
    assert short.value.params == {"length": user_service.MIN_PASSWORD_LENGTH}
    assert str(short.value) == "The password is too short. Use at least 12 characters."

    with pytest.raises(UserAdminError) as bad:
        user_service.normalise_email("not-an-address")
    assert (bad.value.message, bad.value.params) == ("Enter a valid e-mail address.", {})

    member(db_session)
    with pytest.raises(AccountExistsError) as taken:
        user_service.create_user(db_session, "member@example.org", PASSWORD)
    assert str(taken.value) == "An account for this e-mail address exists already."
    assert isinstance(taken.value, UserAdminError)  # whoever catches the family still catches it


def test_an_unknown_account_is_a_message_not_a_crash(db_session: Session) -> None:
    with pytest.raises(UserAdminError, match="no account"):
        user_service.find_user(db_session, "nobody@example.org")


# ------------------------------------------------------------------------------ passwords


def test_a_new_password_signs_the_account_out_everywhere(
    client: FlaskClient, db_session: Session
) -> None:
    user = member(db_session)
    login_as(client, user)
    assert client.get("/assessments/").status_code == 200

    before = user.fs_uniquifier
    user_service.set_password(db_session, "member@example.org", "Another-Strong-Pass-2")
    db_session.commit()

    assert user.fs_uniquifier != before
    assert verify_password("Another-Strong-Pass-2", user.password)
    response = client.get("/assessments/")  # the session carried the old identifier
    assert response.status_code == 302 and "/auth/login" in response.headers["Location"]


def test_the_new_password_must_be_long_enough(db_session: Session) -> None:
    user = member(db_session)
    with pytest.raises(UserAdminError, match="at least 12 characters"):
        user_service.set_password(db_session, user.email, "short")
    assert verify_password(PASSWORD, user.password)


@pytest.mark.parametrize(
    "how", ["create_user", "create_admin", "create_admin_again", "set_password"]
)
def test_a_password_is_stored_the_way_the_sign_in_form_checks_it(
    db_session: Session, how: str
) -> None:
    """The sign-in form normalises what is typed (NFKD) before it checks the hash, so the hash
    must be of the normalised text: a letter typed as one character would never match otherwise."""
    checked = security.password_util.normalize(ACCENTED)
    assert checked != ACCENTED  # the two spellings differ: the case is real
    if how == "create_user":
        user = user_service.create_user(db_session, "a@example.org", ACCENTED)
    elif how == "create_admin":
        user = user_service.create_admin(db_session, "a@example.org", ACCENTED)
    else:
        member(db_session, "a@example.org")
        if how == "create_admin_again":
            user = user_service.create_admin(db_session, "a@example.org", ACCENTED)
        else:
            user = user_service.set_password(db_session, "a@example.org", ACCENTED)
    assert verify_password(checked, user.password)


def test_resetting_an_administrator_with_create_admin_signs_it_out_too(db_session: Session) -> None:
    boss = user_service.create_admin(db_session, "boss@example.org", PASSWORD)
    before = boss.fs_uniquifier
    user_service.create_admin(db_session, "boss@example.org", "A-Different-Pass-33")
    assert boss.fs_uniquifier != before and verify_password("A-Different-Pass-33", boss.password)


# ------------------------------------------------------------------------------ switching off


def test_an_account_can_be_switched_off_and_on_again(db_session: Session) -> None:
    user = member(db_session)
    assert user_service.set_active(db_session, user.email, False) is True
    assert user.active is False
    assert user_service.set_active(db_session, user.email, False) is False  # nothing to do
    assert user_service.set_active(db_session, user.email, True) is True and user.active


def test_a_switched_off_account_loses_its_session_at_once(
    client: FlaskClient, db_session: Session
) -> None:
    user = member(db_session)
    login_as(client, user)
    user_service.set_active(db_session, user.email, False)
    db_session.commit()
    assert client.get("/assessments/").status_code == 302


def test_the_last_active_administrator_cannot_be_switched_off(db_session: Session) -> None:
    boss = admin(db_session)
    with pytest.raises(UserAdminError) as refused:
        user_service.set_active(db_session, boss.email, False)
    assert (refused.value.message, refused.value.params) == (SWITCH_OFF_REFUSAL, {})
    assert str(refused.value) == SWITCH_OFF_REFUSAL  # the command line prints it as it stands
    assert boss.active

    second = admin(db_session, "second@example.org")
    assert user_service.set_active(db_session, boss.email, False) is True  # now somebody remains
    with pytest.raises(UserAdminError, match="last active administrator"):
        user_service.set_active(db_session, second.email, False)


def test_a_switched_off_administrator_does_not_count_as_one_who_remains(
    db_session: Session,
) -> None:
    first, second = admin(db_session), admin(db_session, "second@example.org")
    user_service.set_active(db_session, first.email, False)
    with pytest.raises(UserAdminError, match="last active administrator"):
        user_service.set_active(db_session, second.email, False)


# ------------------------------------------------------------------------------ the role


def test_the_administrator_role_can_be_given_and_taken_away(db_session: Session) -> None:
    user, boss = member(db_session), admin(db_session)
    assert user_service.set_admin(db_session, user.email, True) is True
    assert user_service.holds_admin_role(user)
    assert user_service.set_admin(db_session, user.email, True) is False  # already
    assert user_service.set_admin(db_session, user.email, False) is True
    assert not user_service.holds_admin_role(user) and user_service.holds_admin_role(boss)
    assert user_service.set_admin(db_session, user.email, False) is False


def test_the_last_active_administrator_keeps_the_role(db_session: Session) -> None:
    boss = admin(db_session)
    with pytest.raises(UserAdminError) as refused:
        user_service.set_admin(db_session, boss.email, False)
    assert (refused.value.message, refused.value.params) == (ROLE_REFUSAL, {})
    assert str(refused.value) == ROLE_REFUSAL
    assert user_service.holds_admin_role(boss)


# ------------------------------------------------------------------------------ authenticator


def test_a_lost_authenticator_can_be_forgotten(db_session: Session) -> None:
    user = member(db_session)
    user.tf_primary_method, user.tf_totp_secret = "authenticator", "SECRET"
    db_session.commit()

    assert user_service.reset_mfa(db_session, user.email) is True
    assert user.tf_primary_method is None and user.tf_totp_secret is None
    assert user_service.reset_mfa(db_session, user.email) is False  # nothing left to forget


# ------------------------------------------------------------------------------ the list


def test_the_list_names_administrators_first_and_what_each_account_can_do(
    db_session: Session,
) -> None:
    zed, boss = member(db_session, "zed@example.org"), admin(db_session, "boss@example.org")
    ann = member(db_session, "ann@example.org")
    ann.active, ann.tf_primary_method = False, "authenticator"
    db_session.commit()

    rows = user_service.list_users(db_session)
    assert [row.email for row in rows] == [boss.email, ann.email, zed.email]
    assert [(r.admin, r.active, r.mfa) for r in rows] == [
        (True, True, False),
        (False, False, True),
        (False, True, False),
    ]
    assert all(r.created and r.last_login is None for r in rows)


# ------------------------------------------------------------------------------ the log


def test_every_change_is_in_the_audit_log_without_a_password(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.audit"):
        user = member(db_session)
        user_service.set_password(db_session, user.email, "Another-Strong-Pass-2")
        user_service.set_active(db_session, user.email, False)
        user_service.set_admin(db_session, user.email, True)
        user_service.reset_mfa(db_session, user.email)
    entries = audit_rows(db_session)
    assert [e.action for e in entries] == [
        "user.created",
        "user.password_set",
        "user.deactivated",
        "user.admin_granted",
        "user.mfa_reset",
    ]
    # a command line has nobody signed in; the entry says whom it concerned
    assert all(e.actor_id is None and e.source == "cli" for e in entries)
    assert all(e.subject == str(user.id) and e.details["email"] == user.email for e in entries)
    everything = repr([e.details for e in entries]) + caplog.text
    assert PASSWORD not in everything and "Another-Strong" not in everything
