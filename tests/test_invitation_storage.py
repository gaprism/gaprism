"""Storage of one-time links: one row per account and purpose, a unique hash, rows that go with
the account, and the audit labels the later tasks write with."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import User, UserInvitation
from app.models.base import utc_now
from app.service import audit as audit_service
from tests.helpers import create_user


def link(user: User, purpose: str = "invite", token: str | None = None) -> UserInvitation:
    """A row for ``user``; only the hash of a token is ever stored."""
    digest = hashlib.sha256((token or uuid.uuid4().hex).encode()).hexdigest()
    return UserInvitation(
        user_id=user.id,
        purpose=purpose,
        token_hash=digest,
        expires_at=utc_now() + timedelta(hours=72),
    )


def count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(UserInvitation)) or 0


def test_a_user_has_one_link_per_purpose(db_session: Session) -> None:
    user = create_user(db_session)
    db_session.add_all([link(user, "invite"), link(user, "reset")])
    db_session.flush()  # an invitation and a reset link can exist side by side

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(link(user, "invite"))
        db_session.flush()
    assert count(db_session) == 2


def test_a_hash_is_unique(db_session: Session) -> None:
    first, second = create_user(db_session), create_user(db_session)
    db_session.add(link(first, token="the-same-token"))
    db_session.flush()

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(link(second, token="the-same-token"))
        db_session.flush()


def test_the_purpose_is_checked(db_session: Session) -> None:
    user = create_user(db_session)
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(link(user, "other"))
        db_session.flush()


def test_deleting_an_account_deletes_its_links(db_session: Session) -> None:
    user = create_user(db_session)
    db_session.add_all([link(user, "invite"), link(user, "reset")])
    db_session.flush()
    assert count(db_session) == 2

    db_session.execute(delete(User).where(User.id == user.id))
    assert count(db_session) == 0


def test_a_link_knows_its_account_and_starts_unrevoked(db_session: Session) -> None:
    user = create_user(db_session)
    row = link(user)
    db_session.add(row)
    db_session.flush()
    assert row.user.email == user.email
    assert row.revoked_at is None and row.reset_authenticator is False and row.created_at


@pytest.mark.parametrize(
    "action",
    [
        "user.invited",
        "user.invitation_used",
        "user.invitation_revoked",
        "user.reset_link_created",
        "user.sessions_ended",
    ],
)
def test_the_new_actions_have_labels(action: str) -> None:
    assert action in audit_service.ACTIONS
    assert audit_service.action_label(action) != action
