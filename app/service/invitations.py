"""One-time links: an invitation for a new account, a reset for an existing one.

A link is 32 random bytes in URL-safe text. Only its SHA-256 is kept, so nobody who reads the
database can use a link, and an account has at most one link per purpose: a new one replaces the
old. Using a link deletes its row, which is also how an account stops being "invited". Callers
commit; every change is written to the audit log in the same transaction, never with the token.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.auth import User
from app.models.base import utc_now
from app.models.invitation import UserInvitation
from app.service import audit as audit_service
from app.service import users as user_service
from app.service.users import UserAdminError

INVITE = "invite"
RESET = "reset"
MAX_OPEN_LINKS = 200  # links that work at this moment, over all accounts
TOKEN_BYTES = 32
TOKEN_LENGTH = -(-TOKEN_BYTES * 4 // 3)  # 32 bytes in URL-safe base64 without padding: 43
_TOKEN_SHAPE = re.compile(f"[A-Za-z0-9_-]{{{TOKEN_LENGTH}}}")
INVITATION_PATH = "/auth/invitation/"


class InvalidLinkError(Exception):
    """The link is unknown, used, withdrawn or expired, or its account is switched off.

    One message for all of them: whoever holds a dead link learns nothing about which it is.
    """

    def __init__(self) -> None:
        super().__init__("This link does not work.")


@dataclass(frozen=True)
class IssuedLink:
    token: str  # shown once to whoever made it; never stored
    expires_at: datetime
    purpose: str


def link_path(token: str) -> str:
    """The path of the page where the link is used (the address of the site goes in front)."""
    return f"{INVITATION_PATH}{token}"


def looks_like_token(text: str) -> bool:
    """Is ``text`` shaped like a link's token? A cheap check before the database is asked."""
    return _TOKEN_SHAPE.fullmatch(text) is not None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _record(
    session: Session, action: str, user: User, *, actor: User | None = None, **details: object
) -> None:
    """Write the entry about an account: its id and address, never a token or a password."""
    audit_service.record(
        session, action, actor=actor, subject=str(user.id), details={"email": user.email, **details}
    )


def _is_open(row: UserInvitation, now: datetime) -> bool:
    return row.revoked_at is None and row.expires_at > now


def _own_link(session: Session, user: User, purpose: str) -> UserInvitation | None:
    return session.scalar(
        select(UserInvitation).where(
            UserInvitation.user_id == user.id, UserInvitation.purpose == purpose
        )
    )


def _make_room(session: Session, replacing: UserInvitation | None, now: datetime) -> None:
    """Refuse another working link when 200 work already; replacing a working one is no more."""
    if replacing is not None and _is_open(replacing, now):
        return
    open_links = session.scalar(
        select(func.count())
        .select_from(UserInvitation)
        .where(UserInvitation.revoked_at.is_(None), UserInvitation.expires_at > now)
    )
    if (open_links or 0) >= MAX_OPEN_LINKS:
        raise UserAdminError(
            "Too many links work at the moment (%(limit)s). Withdraw some, or wait until they "
            "have expired.",
            limit=MAX_OPEN_LINKS,
        )


def _issue(
    session: Session,
    user: User,
    purpose: str,
    *,
    hours: int,
    authenticator: bool,
    now: datetime,
) -> IssuedLink:
    """Replace the account's link of this purpose by a new one and return the token."""
    old = _own_link(session, user, purpose)
    _make_room(session, old, now)
    if old is not None:
        session.delete(old)
        session.flush()  # the unique (account, purpose) must be free before the new row goes in
    token = secrets.token_urlsafe(TOKEN_BYTES)
    actor = audit_service.current_actor()
    expires_at = now + timedelta(hours=hours)
    session.add(
        UserInvitation(
            user_id=user.id,
            purpose=purpose,
            token_hash=_hash(token),
            reset_authenticator=authenticator and purpose == RESET,
            created_by=actor.id if actor is not None else None,
            created_at=now,
            expires_at=expires_at,
        )
    )
    session.flush()
    if purpose == INVITE:
        _record(session, "user.invited", user, purpose=purpose, hours=hours)
    else:
        _record(
            session, "user.reset_link_created", user, purpose=purpose, authenticator=authenticator
        )
    return IssuedLink(token=token, expires_at=expires_at, purpose=purpose)


def invite_user(
    session: Session, email: str, *, admin: bool, hours: int, now: datetime | None = None
) -> tuple[User, IssuedLink]:
    """Create an account that nobody can sign in to yet, and the link that lets its person set
    a password. The password it starts with is random and thrown away."""
    now = now or utc_now()
    _make_room(session, None, now)  # before the account exists: a refusal leaves nothing behind
    user = user_service.create_user(
        session, email, secrets.token_urlsafe(48), admin=admin, via="invitation"
    )
    return user, _issue(session, user, INVITE, hours=hours, authenticator=False, now=now)


def new_link(
    session: Session, email: str, *, authenticator: bool, hours: int, now: datetime | None = None
) -> tuple[User, IssuedLink]:
    """A new link for an account: an invitation while it has not accepted one, otherwise a
    reset link (which forgets the authenticator when it is used, if ``authenticator``)."""
    now = now or utc_now()
    user = user_service.find_user(session, email)
    if not user.active:
        raise UserAdminError("This account is switched off. Switch it on first.")
    purpose = INVITE if _own_link(session, user, INVITE) is not None else RESET
    link = _issue(session, user, purpose, hours=hours, authenticator=authenticator, now=now)
    return user, link


def revoke_links(session: Session, email: str, *, now: datetime | None = None) -> int:
    """Withdraw the links of an account that work at the moment; how many there were."""
    now = now or utc_now()
    user = user_service.find_user(session, email)
    withdrawn = 0
    for row in session.scalars(select(UserInvitation).where(UserInvitation.user_id == user.id)):
        if _is_open(row, now):
            row.revoked_at = now
            withdrawn += 1
    if withdrawn:
        session.flush()
        _record(session, "user.invitation_revoked", user, count=withdrawn)
    return withdrawn


def _account_is_active(session: Session, user_id: uuid.UUID) -> bool:
    """Whether the account is switched on now: read from the database, not from an object this
    session may hold from earlier in the request."""
    return bool(session.scalar(select(User.active).where(User.id == user_id)))


def _find(session: Session, token: str, now: datetime, *, lock: bool = False) -> UserInvitation:
    statement = select(UserInvitation).where(UserInvitation.token_hash == _hash(token))
    if lock:
        # Locked, and re-read even when this request loaded the row before (the page did): a link
        # withdrawn or replaced in the meantime must not be used.
        statement = statement.with_for_update().execution_options(populate_existing=True)
    row: UserInvitation | None = session.scalar(statement)
    if row is None or not _is_open(row, now) or not _account_is_active(session, row.user_id):
        raise InvalidLinkError
    return row


def open_link(session: Session, token: str, *, now: datetime | None = None) -> UserInvitation:
    """The row of a link that works, to show who it is for. Changes nothing."""
    return _find(session, token, now or utc_now())


def accept_link(
    session: Session, token: str, password: str, *, now: datetime | None = None
) -> User:
    """Set the password of the link's account and use the link up.

    A password that is refused leaves the link as it was. The account's other sessions end, and
    a reset link made with ``authenticator`` makes it forget its authenticator.
    """
    now = now or utc_now()
    row = _find(session, token, now, lock=True)  # locked: two submissions cannot both succeed
    user_service.check_password(password)
    user = row.user
    purpose, forget_authenticator = row.purpose, row.reset_authenticator
    user.password = user_service.hash_new_password(password)
    user_service.end_sessions(user)
    session.delete(row)
    session.flush()
    if forget_authenticator:
        user_service.reset_mfa(session, user.email)
    _record(session, "user.invitation_used", user, actor=user, purpose=purpose)
    return user
