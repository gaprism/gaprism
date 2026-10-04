"""Authentication: admin bootstrap, MFA enrolment, generic failures and throttling."""

from datetime import timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_security.utils import hash_password, verify_password
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models.auth import User
from app.models.auth_rate_limit import AuthRateLimitBucket
from app.models.base import utc_now
from app.service.auth import AuthRateLimiter


def test_cli_create_admin_success(
    app: Flask, cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    """`flask users create-admin` creates an active administrator with a hashed password."""
    result = cli_runner.invoke(
        args=["users", "create-admin", "--email", "  Admin@Example.org "],
        input="StrongAdminPass123!\nStrongAdminPass123!\n",
    )
    assert result.exit_code == 0, result.output
    assert "Administrator 'admin@example.org' is ready." in result.output

    user = db_session.query(User).filter_by(email="admin@example.org").first()
    assert user is not None
    assert user.active is True
    assert user.password != "StrongAdminPass123!"
    assert verify_password("StrongAdminPass123!", user.password)
    assert [role.name for role in user.roles] == ["admin"]


def test_cli_create_admin_resets_an_existing_account(
    app: Flask, cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    """Running the command again resets the password and re-activates the account."""
    existing = User(
        email="again@example.org", password=hash_password("OldPassword123!"), active=False
    )
    db_session.add(existing)
    db_session.commit()

    result = cli_runner.invoke(
        args=["users", "create-admin", "--email", "again@example.org"],
        input="NewPassword123!!\nNewPassword123!!\n",
    )
    assert result.exit_code == 0, result.output
    db_session.refresh(existing)
    assert existing.active is True
    assert verify_password("NewPassword123!!", existing.password)
    assert db_session.query(User).filter_by(email="again@example.org").count() == 1


def test_cli_rejects_short_passwords_and_bad_addresses(
    app: Flask, cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    short = cli_runner.invoke(
        args=["users", "create-admin", "--email", "short@example.org"],
        input="tooshort\ntooshort\n",
    )
    assert short.exit_code != 0
    assert "at least 12 characters" in short.output

    bad = cli_runner.invoke(
        args=["users", "create-admin", "--email", "not-an-address"],
        input="StrongAdminPass123!\nStrongAdminPass123!\n",
    )
    assert bad.exit_code != 0
    assert "valid e-mail address" in bad.output
    assert db_session.query(User).count() == 0


def test_cli_rejects_password_process_argument(cli_runner: FlaskCliRunner) -> None:
    """A password on the command line would leak into the process list and shell history."""
    result = cli_runner.invoke(
        args=[
            "users",
            "create-admin",
            "--email",
            "unsafe@example.org",
            "--password",
            "VisibleInProcessList123!",
        ]
    )
    assert result.exit_code != 0
    assert "No such option '--password'" in result.output


def test_public_registration_is_disabled(client: FlaskClient) -> None:
    """Public registration endpoints must not exist (SECURITY_REGISTERABLE is False)."""
    assert client.get("/auth/register").status_code == 404


def test_password_login_requires_mfa_enrolment(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    """With MFA required, a password-only account is sent to enrolment and is not logged in."""
    user = User(
        email="analyst@example.com",
        password=hash_password("ValidPassword123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={"email": "analyst@example.com", "password": "ValidPassword123!"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/tf-setup" in response.headers.get("Location", "")
    with client.session_transaction() as state:
        assert "_user_id" not in state

    assert client.post("/auth/logout", follow_redirects=True).status_code == 200


def test_login_failures_are_generic_and_rate_limited(
    client: FlaskClient, db_session: Session
) -> None:
    """Unknown and known accounts look identical; repeated failures end in HTTP 429."""
    user = User(
        email="rate-limited@example.org",
        password=hash_password("CorrectPassword123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    known_response = client.post(
        "/auth/login",
        data={"email": user.email, "password": "wrong-password"},
    )
    unknown_response = client.post(
        "/auth/login",
        data={"email": "unknown@example.org", "password": "wrong-password"},
    )
    assert known_response.status_code == unknown_response.status_code == 200
    assert known_response.data.replace(user.email.encode(), b"<identity>") == (
        unknown_response.data.replace(b"unknown@example.org", b"<identity>")
    )

    for _ in range(3):
        response = client.post(
            "/auth/login",
            data={"email": user.email, "password": "wrong-password"},
        )
        assert response.status_code == 200
    bucket_state = sorted(
        (bucket.bucket_kind, bucket.failures)
        for bucket in db_session.query(AuthRateLimitBucket).all()
    )
    assert bucket_state == [("ip", 5), ("principal", 1), ("principal", 4)]
    blocked = client.post(
        "/auth/login",
        data={"email": user.email, "password": "CorrectPassword123!"},
    )
    assert blocked.status_code == 429
    assert b"rate-limited@example.org" not in blocked.data
    assert blocked.mimetype == "text/html"  # the app's error page, not a bare text answer
    assert 0 < int(blocked.headers["Retry-After"]) <= 15 * 60


def block_sign_in(session: Session, email: str = "someone@example.org") -> AuthRateLimiter:
    """Fail often enough from the test client's address that the limiter blocks it."""
    limiter = AuthRateLimiter(session)
    for _ in range(limiter.limit):
        limiter.record_failure("127.0.0.1", email)
    return limiter


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(20, "about 1 minute."), (61, "about 2 minutes."), (15 * 60, "about 15 minutes.")],
)
def test_a_blocked_sign_in_says_how_long_to_wait(
    client: FlaskClient, db_session: Session, seconds: int, expected: str
) -> None:
    block_sign_in(db_session)
    db_session.execute(
        update(AuthRateLimitBucket).values(blocked_until=utc_now() + timedelta(seconds=seconds))
    )
    db_session.commit()

    response = client.post("/auth/login", data={"email": "someone@example.org", "password": "x"})
    page = response.get_data(as_text=True)
    assert response.status_code == 429
    assert "Too many attempts" in page and expected in page
    assert seconds - 2 <= int(response.headers["Retry-After"]) <= seconds
    assert "someone@example.org" not in page


def test_a_block_covers_the_address_and_the_account_until_the_later_end(
    db_session: Session,
) -> None:
    limiter = block_sign_in(db_session)
    window = limiter.window

    remaining = limiter.blocked_for("127.0.0.1", "someone@example.org")
    assert remaining is not None and window - timedelta(seconds=5) < remaining <= window
    # The address blocks every account behind it, the account blocks every address.
    assert limiter.blocked_for("127.0.0.1", "other@example.org") is not None
    assert limiter.blocked_for("203.0.113.9", "someone@example.org") is not None
    assert limiter.blocked_for("203.0.113.9", "other@example.org") is None

    now = utc_now()
    for kind, seconds in (("ip", 30), ("principal", 300)):
        db_session.execute(
            update(AuthRateLimitBucket)
            .where(AuthRateLimitBucket.bucket_kind == kind)
            .values(blocked_until=now + timedelta(seconds=seconds))
        )
    later = limiter.blocked_for("127.0.0.1", "someone@example.org")
    assert later is not None and timedelta(seconds=290) < later <= timedelta(seconds=300)


def test_a_full_window_blocks_even_without_a_block_timestamp_and_expiry_unblocks(
    db_session: Session,
) -> None:
    limiter = block_sign_in(db_session)
    db_session.execute(update(AuthRateLimitBucket).values(blocked_until=None))
    still = limiter.blocked_for("127.0.0.1", "someone@example.org")
    assert still is not None and still > limiter.window - timedelta(seconds=5)

    expired = utc_now() - limiter.window - timedelta(seconds=1)
    db_session.execute(
        update(AuthRateLimitBucket).values(window_started_at=expired, blocked_until=expired)
    )
    assert limiter.blocked_for("127.0.0.1", "someone@example.org") is None


def test_login_invalid_credentials(client: FlaskClient, db_session: Session) -> None:
    user = User(
        email="user1@example.com",
        password=hash_password("CorrectPassword123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={"email": "user1@example.com", "password": "WrongPassword!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_deactivated_user_cannot_login(client: FlaskClient, db_session: Session) -> None:
    user = User(
        email="disabled@example.com",
        password=hash_password("Password123!"),
        active=False,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={"email": "disabled@example.com", "password": "Password123!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
