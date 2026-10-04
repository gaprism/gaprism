"""Multi-factor authentication (TOTP) through Flask-Security-Too."""

import pyotp
from flask import Flask
from flask.testing import FlaskClient
from flask_security.utils import hash_password
from sqlalchemy.orm import Session

from app.extensions import db, security
from app.models.auth import User


def test_mfa_totp_generation_and_validation(app: Flask, db_session: Session) -> None:
    """Verify TOTP token generation and validation against raw user secrets."""
    totp = pyotp.TOTP(pyotp.random_base32())
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
        db.session.flush()

        assert user.tf_totp_secret is not None
        token = totp_factory.generate_totp_password(user.tf_totp_secret)
        assert token is not None

        assert totp_factory.verify_totp(token, user.tf_totp_secret, user) is True
        assert totp_factory.verify_totp("000000", user.tf_totp_secret, user) is False
        db.session.rollback()


def test_mfa_login_challenge_flow(app: Flask, client: FlaskClient, db_session: Session) -> None:
    """A user with MFA is challenged after the password; a wrong code does not log in."""
    totp_secret = security._totp_factory.generate_totp_secret()
    user = User(
        email="mfa_challenge@example.org",
        password=hash_password("SuperSecretPass123!"),
        active=True,
        tf_primary_method="authenticator",
        tf_totp_secret=totp_secret,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={"email": "mfa_challenge@example.org", "password": "SuperSecretPass123!"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/tf-validate" in response.headers.get("Location", "")

    bad_response = client.post("/auth/tf-validate", data={"code": "000000"}, follow_redirects=True)
    assert bad_response.status_code == 200
    with client.session_transaction() as sess:
        assert "_user_id" not in sess

    valid_code = security._totp_factory.generate_totp_password(totp_secret)
    good_response = client.post(
        "/auth/tf-validate", data={"code": valid_code}, follow_redirects=True
    )
    assert good_response.status_code == 200
    with client.session_transaction() as sess:
        assert "_user_id" in sess

    # Deactivating the account revokes the live session on the next request.
    user.active = False
    db_session.commit()
    client.get("/healthz")
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
