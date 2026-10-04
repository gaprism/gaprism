"""Unit and integration tests for authentication and identity management."""

from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_security.utils import hash_password, verify_password
from sqlalchemy.orm import Session

from app.models.auth import Membership, User, Workspace
from app.models.auth_rate_limit import AuthRateLimitBucket


def test_cli_create_admin_success(
    app: Flask, cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    """Verify that 'flask users create-admin' bootstraps admin user, workspace, and membership."""
    result = cli_runner.invoke(
        args=[
            "users",
            "create-admin",
            "--email",
            "admin@example.org",
            "--workspace",
            "Security Team",
        ],
        input="StrongAdminPass123!\nStrongAdminPass123!\n",
    )
    assert result.exit_code == 0
    assert "Successfully bootstrapped admin account 'admin@example.org'" in result.output

    # Query DB to verify records
    user = db_session.query(User).filter_by(email="admin@example.org").first()
    assert user is not None
    assert user.active is True
    assert verify_password("StrongAdminPass123!", user.password)
    assert any(role.name == "admin" for role in user.roles)

    workspace = db_session.query(Workspace).filter_by(name="Security Team").first()
    assert workspace is not None
    assert workspace.enabled is True

    membership = (
        db_session.query(Membership).filter_by(workspace_id=workspace.id, user_id=user.id).first()
    )
    assert membership is not None
    assert membership.role == "admin"
    assert membership.active is True


def test_public_registration_is_disabled(client: FlaskClient) -> None:
    """Verify that public registration endpoints are not enabled."""
    response = client.get("/auth/register")
    # Should be 404 since SECURITY_REGISTERABLE is False
    assert response.status_code == 404


def test_password_login_requires_mfa_enrolment(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    """Verify a password-only account is sent to mandatory MFA enrolment."""
    # Create test user
    user = User(
        email="analyst@example.com",
        password=hash_password("ValidPassword123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    # Login
    response = client.post(
        "/auth/login",
        data={"email": "analyst@example.com", "password": "ValidPassword123!"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/tf-setup" in response.headers.get("Location", "")
    with client.session_transaction() as state:
        assert "_user_id" not in state

    # Logout
    logout_resp = client.post("/auth/logout", follow_redirects=True)
    assert logout_resp.status_code == 200


def test_cli_rejects_password_process_argument(cli_runner: FlaskCliRunner) -> None:
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


def test_login_failures_are_generic_and_rate_limited(
    client: FlaskClient, db_session: Session
) -> None:
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


def test_login_invalid_credentials(client: FlaskClient, db_session: Session) -> None:
    """Verify login failure with wrong password."""
    user = User(
        email="user1@example.com",
        password=hash_password("CorrectPassword123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    # Attempt login with bad password
    response = client.post(
        "/auth/login",
        data={"email": "user1@example.com", "password": "WrongPassword!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    # User should not be authenticated
    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_deactivated_user_cannot_login(client: FlaskClient, db_session: Session) -> None:
    """Verify deactivated user cannot authenticate."""
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
