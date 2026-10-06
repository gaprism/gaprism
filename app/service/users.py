"""User administration: the accounts of the team. Called from the CLI, never from templates.

There is no sign-up and no password-reset mail: an administrator creates the accounts and, when
somebody loses a password or an authenticator, resets it here. Every change is written to the audit
logger (whom it concerned, never a password).
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from flask_security.utils import hash_password
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import AUDIT_LOGGER
from app.models.auth import Role, User

ADMIN_ROLE = "admin"
MIN_PASSWORD_LENGTH = 12
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

audit = logging.getLogger(AUDIT_LOGGER)


class UserAdminError(ValueError):
    """Raised when an account cannot be created or changed as requested."""


def normalise_email(raw: str) -> str:
    """Return the canonical (trimmed, lower-case) e-mail address or raise ``UserAdminError``."""
    email = raw.strip().lower()
    if len(email) > 255 or not _EMAIL.fullmatch(email):
        raise UserAdminError("Enter a valid e-mail address.")
    return email


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserAdminError(
            f"The password must contain at least {MIN_PASSWORD_LENGTH} characters."
        )


def holds_admin_role(user: User) -> bool:
    return any(role.name == ADMIN_ROLE for role in user.roles)


def _admin_role(session: Session) -> Role:
    role = session.scalar(select(Role).where(Role.name == ADMIN_ROLE))
    if role is None:
        role = Role(name=ADMIN_ROLE, description="Administrator")
        session.add(role)
    return role


def find_user(session: Session, raw_email: str) -> User:
    """The account for an e-mail address, or ``UserAdminError`` when there is none."""
    user = session.scalar(select(User).where(User.email == normalise_email(raw_email)))
    if user is None:
        raise UserAdminError("There is no account for this e-mail address.")
    return cast(User, user)  # the Flask-Security mixin makes the model's type opaque to mypy


def _other_active_admins(session: Session, user: User) -> int:
    return (
        session.scalar(
            select(func.count(User.id)).where(
                User.id != user.id,
                User.active.is_(True),
                User.roles.any(Role.name == ADMIN_ROLE),
            )
        )
        or 0
    )


def _keep_an_administrator(session: Session, user: User, what: str) -> None:
    """Refuse a change that would leave nobody who can administer the accounts."""
    if user.active and holds_admin_role(user) and _other_active_admins(session, user) == 0:
        raise UserAdminError(
            f"This is the last active administrator: {what} would leave nobody to administer "
            "the accounts. Create another administrator first."
        )


def _end_sessions(user: User) -> None:
    """Sign the account out everywhere: Flask-Security ties a session to this identifier."""
    user.fs_uniquifier = uuid.uuid4().hex


def create_user(session: Session, email: str, password: str, *, admin: bool = False) -> User:
    """Create an active account (an administrator with ``admin``). The caller commits.

    The password is hashed with the configured Flask-Security scheme.
    """
    clean_email = normalise_email(email)
    _check_password(password)
    if session.scalar(select(User.id).where(User.email == clean_email)) is not None:
        raise UserAdminError(
            "An account for this e-mail address exists already. Use `flask users set-password` "
            "to give it a new password, or `flask users activate` to switch it on again."
        )
    user = User(email=clean_email, password=hash_password(password), active=True)
    session.add(user)
    if admin:
        user.roles.append(_admin_role(session))
    session.flush()
    audit.info("user created: user=%s admin=%s", user.id, admin)
    return user


def create_admin(session: Session, email: str, password: str) -> User:
    """Create an active administrator, or reset the password of an existing account.

    The caller commits. The password is hashed with the configured Flask-Security scheme.
    """
    clean_email = normalise_email(email)
    _check_password(password)
    role = _admin_role(session)
    user = session.scalar(select(User).where(User.email == clean_email))
    created = user is None
    if user is None:
        user = User(email=clean_email, password=hash_password(password), active=True)
        session.add(user)
    else:
        user.password = hash_password(password)
        user.active = True
        _end_sessions(user)
    if role not in user.roles:
        user.roles.append(role)
    session.flush()
    audit.info("user %s as administrator: user=%s", "created" if created else "reset", user.id)
    return user


def set_password(session: Session, email: str, password: str) -> User:
    """Give an account a new password and sign it out everywhere. The caller commits."""
    user = find_user(session, email)
    _check_password(password)
    user.password = hash_password(password)
    _end_sessions(user)
    session.flush()
    audit.info("user password set: user=%s", user.id)
    return user


def set_active(session: Session, email: str, active: bool) -> bool:
    """Switch an account off (its sessions end with the next request) or on again. Returns
    whether anything changed."""
    user = find_user(session, email)
    if user.active == active:
        return False
    if not active:
        _keep_an_administrator(session, user, "deactivating it")
    user.active = active
    session.flush()
    audit.info("user %s: user=%s", "activated" if active else "deactivated", user.id)
    return True


def set_admin(session: Session, email: str, admin: bool) -> bool:
    """Give an account the administrator role, or take it away. Returns whether anything changed."""
    user = find_user(session, email)
    if holds_admin_role(user) == admin:
        return False
    if admin:
        user.roles.append(_admin_role(session))
    else:
        _keep_an_administrator(session, user, "taking the role away")
        user.roles = [role for role in user.roles if role.name != ADMIN_ROLE]
    session.flush()
    audit.info("user %s the administrator role: user=%s", "got" if admin else "lost", user.id)
    return True


def reset_mfa(session: Session, email: str) -> bool:
    """Forget the authenticator of an account (somebody lost the phone). With MFA required the
    person enrols again at the next sign-in. Returns whether there was one."""
    user = find_user(session, email)
    had = user.tf_primary_method is not None or user.tf_totp_secret is not None
    user.tf_primary_method = None
    user.tf_totp_secret = None
    session.flush()
    audit.info("user authenticator reset: user=%s had=%s", user.id, had)
    return had


@dataclass(frozen=True)
class UserRow:
    email: str
    admin: bool
    active: bool
    mfa: bool  # an authenticator is enrolled
    last_login: datetime | None
    created: datetime


def list_users(session: Session) -> list[UserRow]:
    """Every account, administrators first, then by e-mail address."""
    rows = [
        UserRow(
            email=user.email,
            admin=holds_admin_role(user),
            active=user.active,
            mfa=user.tf_primary_method is not None,
            last_login=user.last_login_at,
            created=user.create_datetime,
        )
        for user in session.scalars(select(User))
    ]
    return sorted(rows, key=lambda row: (not row.admin, row.email))
