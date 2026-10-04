"""User administration: creating team accounts. Called from the CLI, never from templates."""

from __future__ import annotations

import re

from flask_security.utils import hash_password
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import Role, User

ADMIN_ROLE = "admin"
MIN_PASSWORD_LENGTH = 12
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class UserAdminError(ValueError):
    """Raised when an account cannot be created or changed as requested."""


def normalise_email(raw: str) -> str:
    """Return the canonical (trimmed, lower-case) e-mail address or raise ``UserAdminError``."""
    email = raw.strip().lower()
    if len(email) > 255 or not _EMAIL.fullmatch(email):
        raise UserAdminError("Enter a valid e-mail address.")
    return email


def create_admin(session: Session, email: str, password: str) -> User:
    """Create an active administrator, or reset the password of an existing account.

    The caller commits. The password is hashed with the configured Flask-Security scheme.
    """
    clean_email = normalise_email(email)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserAdminError(
            f"The password must contain at least {MIN_PASSWORD_LENGTH} characters."
        )

    role = session.scalar(select(Role).where(Role.name == ADMIN_ROLE))
    if role is None:
        role = Role(name=ADMIN_ROLE, description="Administrator")
        session.add(role)

    user = session.scalar(select(User).where(User.email == clean_email))
    if user is None:
        user = User(email=clean_email, password=hash_password(password), active=True)
        session.add(user)
    else:
        user.password = hash_password(password)
        user.active = True
    if role not in user.roles:
        user.roles.append(role)
    session.flush()
    return user
