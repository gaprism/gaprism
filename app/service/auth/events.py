"""Sign-in events for the audit log: who signed in or out, failed to, changed the password or the
two-factor setup.

Flask-Security (and Flask-Login under it) send a signal for each; this writes the entry in the same
request. A failed sign-in is recorded only for an account that exists: the address somebody typed
for one that does not may be a password in the wrong field, and strangers must not be able to fill
the log (the sign-in limit already caps the failures per account).
"""

from __future__ import annotations

from typing import Any

from flask import Flask, has_request_context
from flask_login import user_logged_out
from flask_security import (
    password_changed,
    tf_disabled,
    tf_profile_changed,
    user_authenticated,
    user_failed_authn,
)

from app.extensions import db
from app.models.auth import User
from app.service import audit as audit_service


def _record(action: str, user: object | None, **details: Any) -> None:
    if not has_request_context() or not isinstance(user, User):
        return
    audit_service.record(db.session(), action, actor=user, details=details)
    db.session.commit()


def register_auth_audit(app: Flask) -> None:
    """Connect the audit log to the sign-in signals."""

    def signed_in(sender: Flask, user: object = None, authn_via: Any = None, **extra: Any) -> None:
        via = [str(method) for method in authn_via or []]
        if via == ["change"]:
            return  # changing the password renews the session; "password changed" says it
        _record("auth.login", user, via=via)

    def signed_out(sender: Flask, user: object = None, **extra: Any) -> None:
        _record("auth.logout", user)

    def failed(sender: Flask, user: object = None, tfa: bool = False, **extra: Any) -> None:
        # A fact only when the second step failed: an entry without it is a wrong password.
        _record("auth.login_failed", user, second_factor=True if tfa else None)

    def password(sender: Flask, user: object = None, **extra: Any) -> None:
        _record("auth.password_changed", user)

    def two_factor(sender: Flask, user: object = None, **extra: Any) -> None:
        _record("auth.mfa_changed", user)

    for signal, receiver in (
        (user_authenticated, signed_in),
        (user_logged_out, signed_out),
        (user_failed_authn, failed),
        (password_changed, password),
        (tf_profile_changed, two_factor),
        (tf_disabled, two_factor),
    ):
        signal.connect(receiver, sender=app, weak=False)
