"""The page where an invited person sets a password: public by design, so it says as little as it
can, pauses an address that keeps guessing, and keeps the link out of logs and referrers."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import timedelta

import pytest
from flask import Flask, url_for
from flask.testing import FlaskClient
from flask_security.utils import verify_password
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User, UserInvitation
from app.models.base import utc_now
from app.service import invitations
from app.service import users as user_service
from tests.helpers import create_user, make_app

GOOD = "A-Long-Enough-Pass-1"
EMAIL = "new@example.org"


def invited(
    session: Session, email: str = EMAIL, *, authenticator: bool = False
) -> tuple[User, str]:
    """An account with an open link, committed. With ``authenticator`` it is a reset link."""
    if authenticator:
        user = user_service.create_user(session, email, GOOD)
        _, link = invitations.new_link(session, email, authenticator=True, hours=72)
    else:
        user, link = invitations.invite_user(session, email, admin=False, hours=72)
    session.commit()
    return user, link.token


def path(token: str) -> str:
    return invitations.link_path(token)


def body(response: object) -> str:
    return response.get_data(as_text=True)  # type: ignore[attr-defined,no-any-return]


# ------------------------------------------------------------------------------ the page


def test_the_page_shows_only_the_address_and_changes_nothing(
    client: FlaskClient, db_session: Session
) -> None:
    user, token = invited(db_session)
    response = client.get(path(token))
    html = body(response)

    assert response.status_code == 200 and EMAIL in html
    assert token not in html  # the page never repeats the link
    assert '<meta name="referrer" content="no-referrer">' in html
    assert response.headers["Cache-Control"] == "no-store"
    assert db_session.scalars(select(UserInvitation)).one().user_id == user.id
    assert not verify_password(GOOD, user.password)


def test_a_reset_link_page_says_the_authenticator_will_be_forgotten(
    client: FlaskClient, db_session: Session
) -> None:
    _, plain = invited(db_session, "plain@example.org")
    _, reset = invited(db_session, "lost@example.org", authenticator=True)
    assert "will be forgotten" not in body(client.get(path(plain)))
    assert "will be forgotten" in body(client.get(path(reset)))


def test_a_good_password_sets_it_and_sends_the_person_to_sign_in(
    client: FlaskClient, db_session: Session
) -> None:
    user, token = invited(db_session)
    response = client.post(path(token), data={"password": GOOD, "confirm": GOOD})
    assert response.status_code == 302 and response.headers["Location"].endswith("/auth/login")
    db_session.refresh(user)
    assert verify_password(GOOD, user.password)

    assert "Password set. Sign in to finish setting up." in body(client.get("/auth/login"))
    again = client.get(path(token))  # used up
    assert again.status_code == 404 and "This link does not work" in body(again)


def test_a_mistyped_or_short_password_shows_the_form_again_and_keeps_the_link(
    client: FlaskClient, db_session: Session
) -> None:
    user, token = invited(db_session)
    for password, confirm, message in (
        (GOOD, GOOD + "x", "not the same"),
        ("short", "short", "at least 12 characters"),
        ("", "", "required"),
    ):
        response = client.post(path(token), data={"password": password, "confirm": confirm})
        assert response.status_code == 200 and message in body(response), message
        assert db_session.scalars(select(UserInvitation)).one().user_id == user.id

    done = client.post(path(token), data={"password": GOOD, "confirm": GOOD})
    assert done.status_code == 302  # the same link still worked


def test_with_mfa_required_the_first_sign_in_asks_for_an_authenticator(
    client: FlaskClient, db_session: Session
) -> None:
    user, token = invited(db_session)
    client.post(path(token), data={"password": GOOD, "confirm": GOOD})
    response = client.post("/auth/login", data={"email": user.email, "password": GOOD})
    assert response.status_code == 302 and "/auth/tf-setup" in response.headers["Location"]


# ------------------------------------------------------------------------------ dead links


def test_every_dead_link_gives_the_same_page(
    client: FlaskClient, db_session: Session, app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "AUTH_RATE_LIMIT_FAILURES", 1000)  # many dead links here
    _, expired = invited(db_session, "expired@example.org")
    row = db_session.scalars(select(UserInvitation)).one()
    row.expires_at = utc_now() - timedelta(hours=1)
    db_session.commit()
    withdrawn_user, withdrawn = invited(db_session, "withdrawn@example.org")
    invitations.revoke_links(db_session, withdrawn_user.email)
    off_user, off = invited(db_session, "off@example.org")
    user_service.set_active(db_session, off_user.email, False)
    _, used = invited(db_session, "used@example.org")
    invitations.accept_link(db_session, used, GOOD)
    db_session.commit()

    dead = [
        expired,
        withdrawn,
        off,
        used,
        secrets.token_urlsafe(32),  # well formed, never issued
        "short",  # not a link at all
        "x" * 2000,
    ]
    pages = {body(client.get(path(token))) for token in dead}
    assert len(pages) == 1
    assert "This link does not work" in pages.pop()
    for token in dead:
        assert client.get(path(token)).status_code == 404
        response = client.post(path(token), data={"password": GOOD, "confirm": GOOD})
        assert response.status_code == 404
    assert not verify_password(GOOD, off_user.password)


def test_five_dead_links_pause_the_address(
    client: FlaskClient, db_session: Session, app: Flask
) -> None:
    user, token = invited(db_session)
    for _ in range(app.config["AUTH_RATE_LIMIT_FAILURES"]):
        assert client.get(path(secrets.token_urlsafe(32))).status_code == 404

    paused = client.get(path(token))  # even the right link waits
    assert paused.status_code == 429 and int(paused.headers["Retry-After"]) > 0
    posted = client.post(path(token), data={"password": GOOD, "confirm": GOOD})
    assert posted.status_code == 429
    assert not verify_password(GOOD, user.password)
    assert db_session.scalars(select(UserInvitation)).one().user_id == user.id


def test_the_form_needs_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        user = create_user(db.session())
        token = secrets.token_urlsafe(32)
        db.session.add(
            UserInvitation(
                user_id=user.id,
                purpose="invite",
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=utc_now() + timedelta(hours=1),
            )
        )
        db.session.commit()
        try:
            response = app.test_client().post(path(token), data={"password": GOOD, "confirm": GOOD})
            assert response.status_code == 400
            db.session.refresh(user)
            assert not verify_password(GOOD, user.password)
            assert db.session.scalars(select(UserInvitation)).one().user_id == user.id
        finally:
            db.session.delete(user)  # its link goes with it
            db.session.commit()


# ------------------------------------------------------------------------------ logs, paths


def test_the_pages_write_no_token_to_the_log(
    client: FlaskClient, db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    _, token = invited(db_session)
    with caplog.at_level(logging.DEBUG):
        client.get(path(token))
        client.post(path(token), data={"password": GOOD, "confirm": GOOD})
    assert token not in caplog.text
    assert any(record.getMessage().startswith("user.invitation_used") for record in caplog.records)


def test_the_route_matches_the_service_path(app: Flask) -> None:
    with app.test_request_context():
        assert url_for("invitation.accept", token="abc") == invitations.link_path("abc")
