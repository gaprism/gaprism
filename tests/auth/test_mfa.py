"""Unit and integration tests for Multi-Factor Authentication (MFA / TOTP)."""

import pyotp
from flask import Flask
from flask.testing import FlaskClient
from flask_security.utils import hash_password
from sqlalchemy.orm import Session

from app.extensions import db, security
from app.models.auth import User


def test_mfa_totp_generation_and_validation(app: Flask, db_session: Session) -> None:
    """Verify TOTP token generation and validation against raw user secrets."""
    totp_secret = pyotp.random_base32()
    user = User(
        email="mfa_user@example.org",
        password=hash_password("Password123!"),
        active=True,
    )
    db_session.add(user)
    db_session.commit()

    # Generate current TOTP code using pyotp
    totp = pyotp.TOTP(totp_secret)
    current_token = totp.now()

    assert totp.verify(current_token) is True
    assert totp.verify("000000") is False


def test_flask_security_totp_factory_workflow(app: Flask) -> None:
    """Verify Flask-Security-Too TOTP factory secret generation and validation."""
    with app.app_context():
        totp_factory = security._totp_factory
        assert totp_factory is not None

        user = User(
            email="mfa_factory@example.org",
            password=hash_password("Password123!"),
            active=True,
            tf_primary_method="authenticator",
            tf_totp_secret=totp_factory.generate_totp_secret(),
        )
        db.session.add(user)
        db.session.commit()

        # Generate valid token and verify
        assert user.tf_totp_secret is not None
        token = totp_factory.generate_totp_password(user.tf_totp_secret)
        assert token is not None

        assert totp_factory.verify_totp(token, user.tf_totp_secret, user) is True
        assert totp_factory.verify_totp("000000", user.tf_totp_secret, user) is False


def test_mfa_login_challenge_flow(app: Flask, client: FlaskClient) -> None:
    """Verify that user with MFA configured undergoes two-factor validation during login."""
    with app.app_context():
        totp_factory = security._totp_factory
        totp_secret = totp_factory.generate_totp_secret()

        user = User(
            email="mfa_challenge@example.org",
            password=hash_password("SuperSecretPass123!"),
            active=True,
            tf_primary_method="authenticator",
            tf_totp_secret=totp_secret,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    # Step 1: Initial password login
    response = client.post(
        "/auth/login",
        data={"email": "mfa_challenge@example.org", "password": "SuperSecretPass123!"},
        follow_redirects=False,
    )

    # Should redirect to tf-validate
    assert response.status_code == 302
    assert "/tf-validate" in response.headers.get("Location", "")

    # Step 2: Attempt validation with invalid code
    bad_resp = client.post(
        "/auth/tf-validate",
        data={"code": "000000"},
        follow_redirects=True,
    )
    assert bad_resp.status_code == 200

    # User not yet fully authenticated in session
    with client.session_transaction() as sess:
        assert "_user_id" not in sess

    # Step 3: Validate with correct TOTP code
    with app.app_context():
        valid_code = security._totp_factory.generate_totp_password(totp_secret)

    good_resp = client.post(
        "/auth/tf-validate",
        data={"code": valid_code},
        follow_redirects=True,
    )
    assert good_resp.status_code == 200

    # User is now fully authenticated
    with client.session_transaction() as sess:
        assert "_user_id" in sess

    with app.app_context():
        stored_user = db.session.get(User, user_id)
        assert stored_user is not None
        stored_user.active = False
        db.session.commit()

    denied = client.get("/assessments/00000000-0000-0000-0000-000000000001")
    assert denied.status_code == 401
