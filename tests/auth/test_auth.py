"""Unit and integration tests for authentication and identity management."""

from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_security.utils import hash_password, verify_password
from sqlalchemy.orm import Session

from app.models.auth import Membership, User, Workspace


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
            "--password",
            "StrongAdminPass123!",
            "--workspace",
            "Security Team",
        ]
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
        db_session.query(Membership)
        .filter_by(workspace_id=workspace.id, user_id=user.id)
        .first()
    )
    assert membership is not None
    assert membership.role == "admin"
    assert membership.active is True


def test_public_registration_is_disabled(client: FlaskClient) -> None:
    """Verify that public registration endpoints are not enabled."""
    response = client.get("/auth/register")
    # Should be 404 since SECURITY_REGISTERABLE is False
    assert response.status_code == 404


def test_login_success_and_logout(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    """Verify standard user login and logout flow."""
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
        follow_redirects=True,
    )
    assert response.status_code == 200

    # Logout
    logout_resp = client.get("/auth/logout", follow_redirects=True)
    assert logout_resp.status_code == 200


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
