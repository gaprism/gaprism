"""One-time links: making them, withdrawing them, using them up, and what they do to the rules of
the accounts. The token itself must never be kept: only its hash is."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from flask_security.utils import verify_password
from sqlalchemy import Update, func, select, update
from sqlalchemy.orm import Session

from app.models import User, UserInvitation
from app.models.base import utc_now
from app.service import invitations
from app.service import users as user_service
from app.service.invitations import InvalidLinkError
from app.service.users import UserAdminError
from tests.helpers import audit_rows

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
GOOD = "A-Long-Enough-Pass-1"
ADMIN_PASSWORD = "Administrator-Pass-1"


def invite(
    session: Session, email: str = "new@example.org", *, admin: bool = False, hours: int = 72
) -> tuple[User, invitations.IssuedLink]:
    return invitations.invite_user(session, email, admin=admin, hours=hours, now=NOW)


def rows(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(UserInvitation)) or 0


def member(session: Session, email: str = "member@example.org") -> User:
    user = user_service.create_user(session, email, GOOD)
    session.commit()
    return user


def changed_elsewhere(session: Session, statement: Update) -> None:
    """Change a row the way another request's transaction would: the objects this session loaded
    earlier in the request do not hear of it."""
    session.execute(statement.execution_options(synchronize_session=False))


# ------------------------------------------------------------------------------ inviting


def test_inviting_makes_an_account_nobody_can_sign_in_to(db_session: Session) -> None:
    user, link = invite(db_session, " New@Example.org ")
    assert user.email == "new@example.org" and user.active
    assert not user_service.holds_admin_role(user)
    assert not verify_password(link.token, user.password)  # the link is not the password

    boss, _ = invite(db_session, "boss@example.org", admin=True)
    assert user_service.holds_admin_role(boss)


def test_the_link_is_random_and_only_its_hash_is_stored(db_session: Session) -> None:
    user, link = invite(db_session)
    row = db_session.scalar(select(UserInvitation).where(UserInvitation.user_id == user.id))
    assert row is not None
    assert len(link.token) == 43 and link.purpose == invitations.INVITE
    assert row.token_hash == hashlib.sha256(link.token.encode()).hexdigest()
    assert link.token not in str(row.__dict__)
    assert link.expires_at == NOW + timedelta(hours=72) == row.expires_at
    assert row.created_by is None  # made without a signed-in administrator: a command line

    _, other = invite(db_session, "other@example.org")
    assert other.token != link.token
    assert invitations.link_path("abc") == "/auth/invitation/abc"


def test_inviting_writes_entries_without_the_token(db_session: Session) -> None:
    _, link = invite(db_session)
    (created,) = audit_rows(db_session, "user.created")
    (invited,) = audit_rows(db_session, "user.invited")
    assert created.details["via"] == "invitation" and created.details["admin"] is False
    assert invited.details["purpose"] == "invite" and invited.details["hours"] == 72
    for event in audit_rows(db_session):
        assert link.token not in json.dumps(event.details)
        assert link.token not in (event.subject or "")


def test_an_address_with_an_account_cannot_be_invited(db_session: Session) -> None:
    member(db_session)
    with pytest.raises(UserAdminError, match="exists already"):
        invite(db_session, "MEMBER@example.org")
    assert rows(db_session) == 0


# ------------------------------------------------------------------------------ new links


def test_a_new_link_replaces_the_old_one(db_session: Session) -> None:
    user, first = invite(db_session)
    _, second = invitations.new_link(db_session, user.email, authenticator=False, hours=72, now=NOW)
    with pytest.raises(InvalidLinkError):
        invitations.open_link(db_session, first.token, now=NOW)
    assert invitations.open_link(db_session, second.token, now=NOW).user_id == user.id
    assert rows(db_session) == 1


def test_an_invited_account_gets_an_invitation_link_and_an_active_one_a_reset_link(
    db_session: Session,
) -> None:
    user, link = invite(db_session)
    _, again = invitations.new_link(db_session, user.email, authenticator=True, hours=72, now=NOW)
    row = invitations.open_link(db_session, again.token, now=NOW)
    assert again.purpose == invitations.INVITE and row.reset_authenticator is False

    invitations.accept_link(db_session, again.token, GOOD, now=NOW)  # now it has a password
    _, reset = invitations.new_link(db_session, user.email, authenticator=True, hours=72, now=NOW)
    row = invitations.open_link(db_session, reset.token, now=NOW)
    assert reset.purpose == invitations.RESET and row.reset_authenticator is True
    (made,) = audit_rows(db_session, "user.reset_link_created")
    assert made.details["purpose"] == "reset" and made.details["authenticator"] is True
    assert link.token not in json.dumps(made.details)


def test_no_link_for_a_switched_off_account(db_session: Session) -> None:
    user = member(db_session)
    user_service.set_active(db_session, user.email, False)
    with pytest.raises(UserAdminError, match="switched off"):
        invitations.new_link(db_session, user.email, authenticator=False, hours=72, now=NOW)
    assert rows(db_session) == 0


def test_at_most_200_links_are_open(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(invitations, "MAX_OPEN_LINKS", 2)
    first, _ = invite(db_session, "a@example.org")
    invite(db_session, "b@example.org")
    with pytest.raises(UserAdminError, match="Too many links"):
        invite(db_session, "c@example.org")
    assert (
        db_session.query(User).filter_by(email="c@example.org").count() == 0
    )  # not even the account

    invitations.new_link(db_session, first.email, authenticator=False, hours=72, now=NOW)
    assert rows(db_session) == 2  # replacing an account's own link is not a third one


# ------------------------------------------------------------------------------ withdrawing


def test_withdrawing_links(db_session: Session) -> None:
    user, link = invite(db_session)
    assert invitations.revoke_links(db_session, user.email, now=NOW) == 1
    with pytest.raises(InvalidLinkError):
        invitations.open_link(db_session, link.token, now=NOW)
    (event,) = audit_rows(db_session, "user.invitation_revoked")
    assert event.details["count"] == 1

    assert invitations.revoke_links(db_session, user.email, now=NOW) == 0
    assert len(audit_rows(db_session, "user.invitation_revoked")) == 1  # nothing to say twice


# ------------------------------------------------------------------------------ using a link


def test_accepting_sets_the_password_uses_up_the_link_and_ends_sessions(
    db_session: Session,
) -> None:
    user, link = invite(db_session)
    before = user.fs_uniquifier
    accepted = invitations.accept_link(db_session, link.token, GOOD, now=NOW)

    assert accepted.id == user.id and verify_password(GOOD, user.password)
    assert user.fs_uniquifier != before  # every session of the account is over
    assert rows(db_session) == 0
    with pytest.raises(InvalidLinkError):
        invitations.accept_link(db_session, link.token, GOOD, now=NOW)
    (used,) = audit_rows(db_session, "user.invitation_used")
    assert used.details["purpose"] == "invite" and used.actor_id == user.id


def test_a_password_that_is_too_short_does_not_use_up_the_link(db_session: Session) -> None:
    user, link = invite(db_session)
    with pytest.raises(UserAdminError, match="at least 12 characters"):
        invitations.accept_link(db_session, link.token, "short", now=NOW)
    assert rows(db_session) == 1 and not verify_password("short", user.password)

    invitations.accept_link(db_session, link.token, GOOD, now=NOW)
    assert verify_password(GOOD, user.password)


def test_a_link_withdrawn_after_the_page_opened_it_is_refused(db_session: Session) -> None:
    user, link = invite(db_session)
    held = invitations.open_link(db_session, link.token, now=NOW)  # the page holds the row ...
    changed_elsewhere(  # ... while an administrator withdraws the link in another request
        db_session,
        update(UserInvitation).where(UserInvitation.id == held.id).values(revoked_at=NOW),
    )
    with pytest.raises(InvalidLinkError):
        invitations.accept_link(db_session, link.token, GOOD, now=NOW)
    assert not verify_password(GOOD, user.password)
    assert rows(db_session) == 1


def test_an_account_switched_off_after_the_page_opened_the_link_gets_no_password(
    db_session: Session,
) -> None:
    user, link = invite(db_session)
    invitations.open_link(db_session, link.token, now=NOW)  # the page has looked at the account
    changed_elsewhere(db_session, update(User).where(User.id == user.id).values(active=False))
    with pytest.raises(InvalidLinkError):
        invitations.accept_link(db_session, link.token, GOOD, now=NOW)
    assert not verify_password(GOOD, user.password)
    assert rows(db_session) == 1


def test_expired_withdrawn_unknown_and_switched_off_links_fail_alike(db_session: Session) -> None:
    messages: set[str] = set()

    def fails(token: str, *, now: datetime = NOW) -> None:
        with pytest.raises(InvalidLinkError) as raised:
            invitations.accept_link(db_session, token, GOOD, now=now)
        messages.add(str(raised.value))

    expired, link = invite(db_session, "expired@example.org")
    fails(link.token, now=NOW + timedelta(hours=73))

    withdrawn, link = invite(db_session, "withdrawn@example.org")
    invitations.revoke_links(db_session, withdrawn.email, now=NOW)
    fails(link.token)

    off, link = invite(db_session, "off@example.org")
    user_service.set_active(db_session, off.email, False)
    fails(link.token)

    fails("this-token-was-never-issued")

    assert len(messages) == 1  # nobody learns which of the four it was
    for user in (expired, withdrawn, off):
        assert not verify_password(GOOD, user.password)


def test_a_reset_link_can_forget_the_authenticator_when_it_is_used(db_session: Session) -> None:
    user = member(db_session)
    user.tf_primary_method, user.tf_totp_secret = "authenticator", "secret"
    db_session.commit()
    _, link = invitations.new_link(db_session, user.email, authenticator=True, hours=72, now=NOW)
    assert (user.tf_primary_method, user.tf_totp_secret) == ("authenticator", "secret")

    invitations.accept_link(db_session, link.token, GOOD, now=NOW)
    assert (user.tf_primary_method, user.tf_totp_secret) == (None, None)
    assert len(audit_rows(db_session, "user.mfa_reset")) == 1


# ------------------------------------------------------------------------------ account rules


def test_the_last_administrator_guard_ignores_an_invitee(db_session: Session) -> None:
    user_service.create_admin(db_session, "a@example.org", ADMIN_PASSWORD)
    _, link = invite(db_session, "b@example.org", admin=True)

    with pytest.raises(UserAdminError, match="last active administrator"):
        user_service.set_active(db_session, "a@example.org", False)
    with pytest.raises(UserAdminError, match="last active administrator"):
        user_service.set_admin(db_session, "a@example.org", False)

    invitations.accept_link(db_session, link.token, GOOD, now=NOW)  # B can administer now
    assert user_service.set_active(db_session, "a@example.org", False) is True


def test_setting_a_password_by_hand_settles_pending_links(db_session: Session) -> None:
    user, _ = invite(db_session)
    user_service.set_password(db_session, user.email, GOOD)
    assert rows(db_session) == 0
    (row,) = user_service.list_users(db_session)
    assert row.invited is False and row.link is None

    boss, _ = invite(db_session, "boss@example.org", admin=True)
    user_service.create_admin(db_session, boss.email, ADMIN_PASSWORD)  # resets a known account
    assert rows(db_session) == 0


def test_list_users_shows_the_state_of_a_link(db_session: Session) -> None:
    now = utc_now()
    invitations.invite_user(db_session, "open@example.org", admin=False, hours=72, now=now)
    invitations.invite_user(
        db_session, "expired@example.org", admin=False, hours=1, now=now - timedelta(hours=2)
    )
    invitations.invite_user(db_session, "withdrawn@example.org", admin=False, hours=72, now=now)
    invitations.revoke_links(db_session, "withdrawn@example.org", now=now)
    _, done = invitations.invite_user(
        db_session, "done@example.org", admin=False, hours=72, now=now
    )
    invitations.accept_link(db_session, done.token, GOOD, now=now)

    by_email = {row.email: row for row in user_service.list_users(db_session)}
    state = {
        email: (row.invited, row.link.state if row.link else None)
        for email, row in by_email.items()
    }
    assert state == {
        "open@example.org": (True, "open"),
        "expired@example.org": (True, "expired"),
        "withdrawn@example.org": (True, "withdrawn"),
        "done@example.org": (False, None),
    }
    assert by_email["open@example.org"].link is not None
    assert by_email["open@example.org"].link.purpose == "invite"
