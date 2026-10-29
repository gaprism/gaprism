"""Database-backed authentication throttling with pseudonymous bucket keys."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
from datetime import UTC, datetime, timedelta

from flask import Flask, Response, current_app, g, has_request_context, request, session
from flask_security import logout_user, user_failed_authn
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from werkzeug.exceptions import TooManyRequests

from app.extensions import db
from app.models.auth import User
from app.models.auth_rate_limit import AuthRateLimitBucket

_RATE_LIMITED_ENDPOINTS = {
    "security.login",
    "security.two_factor_token_validation",
    "security.two_factor_setup_validate",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuthRateLimiter:
    """Apply a fixed-window failure limit to both source IP and principal."""

    def __init__(self, session_: Session) -> None:
        self.session = session_
        self.limit = int(current_app.config["AUTH_RATE_LIMIT_FAILURES"])
        self.window = timedelta(seconds=int(current_app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"]))
        self.key = str(current_app.config["AUTH_RATE_LIMIT_KEY"]).encode("utf-8")

    def _digest(self, kind: str, value: str) -> str:
        message = f"{kind}:{value}".encode()
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _normalise_ip(value: str | None) -> str:
        if not value:
            return "unknown"
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return value.strip().lower()[:255] or "unknown"

    @staticmethod
    def _normalise_principal(value: str | None) -> str | None:
        if not value:
            return None
        normalised = value.strip().casefold()[:255]
        return normalised or None

    def _keys(self, remote_ip: str | None, principal: str | None) -> list[tuple[str, str]]:
        values = [("ip", self._normalise_ip(remote_ip))]
        clean_principal = self._normalise_principal(principal)
        if clean_principal is not None:
            values.append(("principal", clean_principal))
        return [(kind, self._digest(kind, value)) for kind, value in values]

    def blocked_for(self, remote_ip: str | None, principal: str | None) -> timedelta | None:
        """How much longer sign-in stays blocked for this address and account, or ``None``.

        Either bucket can block (an address with too many failures blocks every account behind
        it), so the block lasts until the later of the two ends.
        """
        now = _utc_now()
        cutoff = now - self.window
        keys = [key for _, key in self._keys(remote_ip, principal)]
        rows = self.session.execute(
            select(
                AuthRateLimitBucket.blocked_until,
                AuthRateLimitBucket.window_started_at,
                AuthRateLimitBucket.failures,
            ).where(AuthRateLimitBucket.bucket_key.in_(keys))
        ).all()
        ends: list[datetime] = []
        for blocked_until, window_started_at, failures in rows:
            if blocked_until is not None and blocked_until > now:
                ends.append(blocked_until)
            elif window_started_at > cutoff and failures >= self.limit:
                ends.append(window_started_at + self.window)
        return max(ends) - now if ends else None

    def record_failure(self, remote_ip: str | None, principal: str | None) -> None:
        now = _utc_now()
        cutoff = now - self.window
        blocked_until = now + self.window
        statement = text(
            """
            INSERT INTO auth_rate_limit_bucket (
                bucket_key, bucket_kind, window_started_at, failures,
                blocked_until, updated_at
            ) VALUES (
                :bucket_key, :bucket_kind, :now, 1,
                CASE WHEN :limit <= 1 THEN :blocked_until ELSE NULL END, :now
            )
            ON CONFLICT (bucket_key) DO UPDATE SET
                bucket_kind = EXCLUDED.bucket_kind,
                window_started_at = CASE
                    WHEN auth_rate_limit_bucket.window_started_at <= :cutoff THEN :now
                    ELSE auth_rate_limit_bucket.window_started_at
                END,
                failures = CASE
                    WHEN auth_rate_limit_bucket.window_started_at <= :cutoff THEN 1
                    ELSE auth_rate_limit_bucket.failures + 1
                END,
                blocked_until = CASE
                    WHEN auth_rate_limit_bucket.window_started_at <= :cutoff THEN
                        CASE WHEN :limit <= 1 THEN :blocked_until ELSE NULL END
                    WHEN auth_rate_limit_bucket.failures + 1 >= :limit THEN :blocked_until
                    ELSE auth_rate_limit_bucket.blocked_until
                END,
                updated_at = :now
            """
        )
        for kind, bucket_key in self._keys(remote_ip, principal):
            self.session.execute(
                statement,
                {
                    "bucket_key": bucket_key,
                    "bucket_kind": kind,
                    "now": now,
                    "cutoff": cutoff,
                    "blocked_until": blocked_until,
                    "limit": self.limit,
                },
            )
        self.session.commit()


def reject_blocked_address() -> None:
    """Answer 429 when the limiter has paused the caller's address.

    For pages that take a secret from the URL (the one-time links): a dead link counts as a
    failure of the address, as a wrong password does, and enough of them pause it.
    """
    remaining = AuthRateLimiter(db.session()).blocked_for(request.remote_addr, None)
    if remaining is not None:
        raise TooManyRequests(retry_after=max(1, math.ceil(remaining.total_seconds())))


def record_address_failure() -> None:
    """Count one failure against the caller's address (and commit, as the limiter does)."""
    AuthRateLimiter(db.session()).record_failure(request.remote_addr, None)


def _request_principal(user: object | None = None, tfa: bool = False) -> str | None:
    if tfa and isinstance(user, User):
        return f"user:{user.id}"
    if request.endpoint == "security.login":
        return request.form.get("email") or request.form.get("username")
    pending_user_id = session.get("tf_user_id")
    return f"user:{pending_user_id}" if pending_user_id else None


def register_auth_rate_limit(app: Flask) -> None:
    """Register request gating and Flask-Security failure signal handling."""

    @app.before_request
    def revoke_inactive_session() -> None:
        session_identity = session.get("_user_id")
        if not session_identity:
            return
        is_active = db.session.scalar(
            select(User.active).where(User.fs_uniquifier == str(session_identity))
        )
        if is_active is not True:
            logout_user()
            session.clear()

    @app.before_request
    def reject_blocked_authentication() -> None:
        if request.method != "POST" or request.endpoint not in _RATE_LIMITED_ENDPOINTS:
            return
        g.auth_failure_recorded = False
        limiter = AuthRateLimiter(db.session())
        remaining = limiter.blocked_for(request.remote_addr, _request_principal())
        if remaining is not None:
            # The generic error page says how long to wait; it reveals nothing about the account.
            raise TooManyRequests(retry_after=max(1, math.ceil(remaining.total_seconds())))

    def record_failed_authentication(
        sender: Flask,
        user: object | None = None,
        auth_type: str | None = None,
        tfa: bool = False,
        **extra: object,
    ) -> None:
        del sender, auth_type, extra
        if not has_request_context():
            return
        g.auth_failure_recorded = True
        AuthRateLimiter(db.session()).record_failure(
            request.remote_addr,
            _request_principal(user=user, tfa=tfa),
        )

    user_failed_authn.connect(record_failed_authentication, sender=app, weak=False)

    @app.after_request
    def record_unsignalled_login_failure(response: Response) -> Response:
        if (
            request.method == "POST"
            and request.endpoint == "security.login"
            and 200 <= response.status_code < 300
            and not getattr(g, "auth_failure_recorded", False)
        ):
            AuthRateLimiter(db.session()).record_failure(
                request.remote_addr,
                _request_principal(),
            )
        return response
