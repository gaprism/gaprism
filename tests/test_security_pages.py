"""The password and two-factor pages: the application's own markup for what Flask-Security-Too does.

The library does the work (the checks, the session, the second factor); the pages are ours, in the
voice of the brand: sentence case, a hint for the password manager, a rule that is the one the
accounts have everywhere, and for a problem what happened and what to do. What the forms post is
what the library expects; tests/auth keep the behaviour of the sign-in itself.
"""

from __future__ import annotations

import re

import pyotp
import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_security.utils import verify_password
from sqlalchemy.orm import Session

from app.extensions import security
from app.models.auth import User
from app.service.users import MIN_PASSWORD_LENGTH
from tests.helpers import attributes, audit_rows, create_user, login_as
from tests.test_sign_in_screen import (
    LOST_AUTHENTICATOR,
    WRONG_CODE,
    body_of,
    tag_named,
)

CURRENT = "Throwaway-Password-1"  # what tests.helpers.create_user gives every account
NEW = "Another-Long-Password-2"
# What the library says on these pages, in the words of the application (config.py).
MESSAGES = {
    "INVALID_PASSWORD": (
        "The current password is not correct. Enter the password you sign in with.",
        "error",
    ),
    "RETYPE_PASSWORD_MISMATCH": (
        "The two new passwords are not the same. Enter the same password twice.",
        "error",
    ),
    "PASSWORD_INVALID_LENGTH": (
        "The new password is too short. Use at least %(length)s characters.",
        "error",
    ),
    "PASSWORD_NOT_PROVIDED": ("This field is empty. Enter a password.", "error"),
    "PASSWORD_IS_THE_SAME": (
        "The new password is the same as the current one. Choose a different password.",
        "error",
    ),
    "PASSWORD_CHANGE": ("Your password has been changed.", "success"),
    "TWO_FACTOR_DISABLED": ("Two-factor authentication is turned off.", "success"),
    "TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL": (
        "Two-factor authentication is set up. Use your authenticator app at your next sign-in.",
        "success",
    ),
    "TWO_FACTOR_LOGIN_SUCCESSFUL": ("Your code is confirmed.", "success"),
    "TWO_FACTOR_SETUP_EXPIRED": (
        "The setup took too long: it must be finished within %(within)s. Start again.",
        "error",
    ),
    "TWO_FACTOR_METHOD_NOT_AVAILABLE": (
        "That method is not available. Use the authenticator app.",
        "error",
    ),
    "REAUTHENTICATION_REQUIRED": ("Enter your password to continue.", "info"),
    "REAUTHENTICATION_SUCCESSFUL": ("Your password is confirmed.", "info"),
}
WRONG_CURRENT = MESSAGES["INVALID_PASSWORD"][0]
MISMATCH = MESSAGES["RETYPE_PASSWORD_MISMATCH"][0]
TOO_SHORT = MESSAGES["PASSWORD_INVALID_LENGTH"][0] % {"length": MIN_PASSWORD_LENGTH}
EMPTY = MESSAGES["PASSWORD_NOT_PROVIDED"][0]
SAME = MESSAGES["PASSWORD_IS_THE_SAME"][0]
CHANGED = MESSAGES["PASSWORD_CHANGE"][0]
TURNED_OFF = MESSAGES["TWO_FACTOR_DISABLED"][0]
SET_UP = MESSAGES["TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL"][0]
# What the library says by itself.
LIBRARY_WORDING = (
    "Change Password",
    "New Password",
    "Retype Password",
    "Two-Factor Setup",
    "Two-Factor authentication adds",
    "Currently setup",
    "Submit Code",
    "Submit",
    "Reauthenticate",
    "enter numeric code",
    "Invalid password",
    "Passwords do not match",
    "Password not provided",
    "You successfully",
    "fs-div",
    "fs-menu",
)


def change_password(client: FlaskClient, **data: str) -> str:
    return body_of(client.post("/auth/change-password", data=data))


def signed_in_user(client: FlaskClient, session: Session, *, authenticator: bool = False) -> User:
    user = create_user(session)
    if authenticator:
        user.tf_primary_method = "authenticator"
        user.tf_totp_secret = security._totp_factory.generate_totp_secret()
        session.commit()
    login_as(client, user)
    return user


def button(body: str, text: str) -> dict[str, str]:
    """The attributes of the button that says exactly ``text``."""
    found = re.findall(rf"<button ([^>]*)>{re.escape(text)}</button>", body)
    assert len(found) == 1, f"{len(found)} buttons say {text!r}"
    return attributes(found[0])


def form_of(body: str, name: str) -> dict[str, str]:
    tag = re.search(rf'<form [^>]*name="{name}"[^>]*>', body)
    assert tag is not None, name
    return attributes(tag.group(0))


# ------------------------------------------------------------------------------ the password


def test_the_password_page_is_in_sentence_case_with_help_and_hints_for_the_password_manager(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_user(client, db_session)
    response = client.get("/auth/change-password")
    body = body_of(response)

    assert response.status_code == 200
    assert "<title>Change password · Gaprism</title>" in body and "<h1>Change password</h1>" in body
    for field, label in (
        ("password", "Current password"),
        ("new_password", "New password"),
        ("new_password_confirm", "The same password again"),
    ):
        assert f'<label for="{field}">{label}</label>' in body
    assert attributes(tag_named(body, "password"))["autocomplete"] == "current-password"
    assert attributes(tag_named(body, "new_password"))["autocomplete"] == "new-password"
    assert attributes(tag_named(body, "new_password_confirm"))["autocomplete"] == "new-password"
    assert f'id="new_password-help">At least {MIN_PASSWORD_LENGTH} characters.</p>' in body
    assert "new_password-help" in attributes(tag_named(body, "new_password"))["aria-describedby"]
    assert button(body, "Change password")["class"] == "btn btn-primary"
    assert form_of(body, "change_password_form")["action"] == "/auth/change-password"
    assert '<div class="panel' in body  # the form has a panel of its own, as the other forms do
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def passwords(current: str, new: str, confirm: str | None = None) -> dict[str, str]:
    confirmed = new if confirm is None else confirm
    return {"password": current, "new_password": new, "new_password_confirm": confirmed}


REFUSALS = [
    (passwords("wrong", NEW), WRONG_CURRENT, "password"),
    (passwords(CURRENT, NEW, NEW + "x"), MISMATCH, "new_password_confirm"),
    (passwords(CURRENT, "short"), TOO_SHORT, "new_password"),
    (passwords("", ""), EMPTY, "new_password"),
    (passwords(CURRENT, CURRENT), SAME, "password"),
]


@pytest.mark.parametrize(("data", "message", "field"), REFUSALS)
def test_a_refusal_says_what_happened_and_marks_the_field(
    client: FlaskClient, db_session: Session, data: dict[str, str], message: str, field: str
) -> None:
    signed_in_user(client, db_session)
    body = change_password(client, **data)

    text = re.escape(message)
    assert re.search(rf'<p class="text-sm text-danger" id="{field}-error">{text}</p>', body)
    assert attributes(tag_named(body, field))["aria-invalid"] == "true"
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def test_the_passwords_are_not_put_back_into_the_page(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_user(client, db_session)
    body = change_password(
        client, password=CURRENT, new_password="short", new_password_confirm="short"
    )
    for name in ("password", "new_password", "new_password_confirm"):
        assert attributes(tag_named(body, name)).get("value", "") == ""


def test_a_new_password_needs_the_characters_every_other_account_screen_asks_for(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    """The library's own minimum is 8: nine characters used to change a password that the
    invitation page and the command line would not have accepted."""
    user = signed_in_user(client, db_session)
    assert app.config["SECURITY_PASSWORD_LENGTH_MIN"] == MIN_PASSWORD_LENGTH

    nine = "Abcdefgh1"
    assert len(nine) < MIN_PASSWORD_LENGTH
    body = change_password(client, password=CURRENT, new_password=nine, new_password_confirm=nine)
    assert TOO_SHORT in body
    db_session.refresh(user)
    assert verify_password(CURRENT, user.password)  # nothing was changed

    response = client.post(
        "/auth/change-password",
        data={"password": CURRENT, "new_password": NEW, "new_password_confirm": NEW},
        follow_redirects=True,
    )
    assert CHANGED in body_of(response)
    db_session.refresh(user)
    assert verify_password(NEW, user.password)
    assert [e.actor_id for e in audit_rows(db_session, "auth.password_changed")] == [user.id]


# ------------------------------------------------------------------------------ re-authentication


def test_the_page_that_asks_for_the_password_again_is_ours_too(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_user(client, db_session)
    response = client.get("/auth/verify")
    body = body_of(response)

    assert response.status_code == 200
    assert "<title>Confirm your password · Gaprism</title>" in body
    assert "<h1>Confirm your password</h1>" in body
    assert '<label for="password">Password</label>' in body
    assert attributes(tag_named(body, "password"))["autocomplete"] == "current-password"
    assert button(body, "Continue")["class"] == "btn btn-primary"
    wrong = body_of(client.post("/auth/verify", data={"password": "wrong"}))
    assert WRONG_CURRENT in wrong
    for wording in LIBRARY_WORDING:
        assert wording not in body and wording not in wrong, wording


# ------------------------------------------------------------------------------ two-factor setup


def test_when_two_factor_is_required_and_off_the_page_offers_one_action(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_TWO_FACTOR_REQUIRED", True)
    signed_in_user(client, db_session)
    response = client.get("/auth/tf-setup")
    body = body_of(response)

    assert response.status_code == 200
    assert "<title>Two-factor authentication · Gaprism</title>" in body
    assert "<h1>Two-factor authentication</h1>" in body
    assert "Two-factor authentication is off for your account." in body
    assert form_of(body, "two_factor_setup_form")["action"] == "/auth/tf-setup"
    start = button(body, "Set up an authenticator app")
    assert start["class"] == "btn btn-primary" and start["name"] == "setup"
    assert start["value"] == "authenticator" and start["type"] == "submit"
    assert 'type="radio"' not in body and "Turn off" not in body
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def test_when_it_is_optional_and_on_the_page_offers_to_turn_it_off_and_it_works(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_TWO_FACTOR_REQUIRED", False)
    user = signed_in_user(client, db_session, authenticator=True)
    body = body_of(client.get("/auth/tf-setup"))

    assert "Two-factor authentication is on for your account." in body
    again = button(body, "Set up a new authenticator app")
    assert again["class"] == "btn btn-primary" and again["value"] == "authenticator"
    off = button(body, "Turn off two-factor authentication")
    assert off["class"] == "btn btn-secondary" and off["name"] == "setup"
    assert off["value"] == "disable"
    assert body.index("Set up a new authenticator app") < body.index("Turn off two-factor")

    response = client.post("/auth/tf-setup", data={"setup": "disable"}, follow_redirects=True)
    assert TURNED_OFF in body_of(response)
    db_session.refresh(user)
    assert user.tf_primary_method is None


def test_when_it_is_required_and_on_it_says_why_it_cannot_be_turned_off(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_TWO_FACTOR_REQUIRED", True)
    signed_in_user(client, db_session, authenticator=True)
    body = body_of(client.get("/auth/tf-setup"))

    assert "It is required in this installation, so it cannot be turned off." in body
    assert "Turn off" not in body and 'value="disable"' not in body
    assert "Your current authenticator keeps working until you finish." in body


def choose_the_authenticator(client: FlaskClient) -> str:
    response = client.post("/auth/tf-setup", data={"setup": "authenticator"})
    assert response.status_code == 200
    return body_of(response)


def test_choosing_the_authenticator_shows_the_code_the_key_and_the_step_that_follows(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_user(client, db_session)
    body = choose_the_authenticator(client)

    assert "<h1>Set up two-factor authentication</h1>" in body
    assert "Open an authenticator app on your phone." in body
    image = re.search(r'<img [^>]*id="qrcode"[^>]*>', body)
    assert image is not None
    qr = attributes(image.group(0))
    assert qr["src"].startswith("data:image/svg+xml;base64,")
    assert qr["alt"] == "Code to scan with your authenticator app"
    assert re.search(r"<code[^>]*>[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}</code>", body)  # the key, by hand
    verify = form_of(body, "two_factor_verify_code_form")
    assert verify["action"].startswith("/auth/tf-setup/")  # signed in: the signed state travels
    code = attributes(tag_named(body, "code"))
    assert code["autocomplete"] == "one-time-code" and code["inputmode"] == "numeric"
    assert button(body, "Verify code")["class"] == "btn btn-primary"
    # nothing on the page starts the setup again by accident: that would make a new secret
    assert "two_factor_setup_form" not in body and "Set up an authenticator app" not in body
    start_again = re.search(r'<a class="link" href="([^"]*)">Start again</a>', body)
    assert start_again is not None and start_again.group(1) == "/auth/tf-setup"
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def key_of(body: str) -> str:
    key = re.search(r"<code[^>]*>([A-Z2-7-]+)</code>", body)
    assert key is not None
    return key.group(1).replace("-", "")


def test_the_setup_is_finished_with_the_code_of_the_app(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in_user(client, db_session)
    body = choose_the_authenticator(client)
    code = pyotp.TOTP(key_of(body)).now()

    done = client.post(
        form_of(body, "two_factor_verify_code_form")["action"],
        data={"code": code},
        follow_redirects=True,
    )
    assert SET_UP in body_of(done)
    db_session.refresh(user)
    assert user.tf_primary_method == "authenticator" and user.tf_totp_secret


def test_a_wrong_code_when_you_are_signed_in_goes_back_to_the_start_with_the_reason(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in_user(client, db_session)
    body = choose_the_authenticator(client)

    response = client.post(
        form_of(body, "two_factor_verify_code_form")["action"],
        data={"code": "000000"},
        follow_redirects=True,
    )
    again = body_of(response)
    assert again.count(WRONG_CODE) == 1 and "Set up an authenticator app" in again
    db_session.refresh(user)
    assert user.tf_primary_method is None  # nothing was stored


# ------------------------------------------------------------------------------ the first sign-in


def first_sign_in(client: FlaskClient, session: Session) -> User:
    user = create_user(session)
    response = client.post("/auth/login", data={"email": user.email, "password": CURRENT})
    assert response.status_code == 302 and "/auth/tf-setup" in response.headers["Location"]
    return user


def test_the_first_sign_in_gets_the_same_setup_on_the_page_before_sign_in(
    client: FlaskClient, db_session: Session
) -> None:
    user = first_sign_in(client, db_session)
    page = body_of(client.get("/auth/tf-setup"))

    assert "gaprism-logo-stacked-color.svg" in page  # the layout of the pages before sign-in
    assert "<h1>Two-factor authentication</h1>" in page
    assert "Set up an authenticator app to finish signing in." in page
    assert button(page, "Set up an authenticator app")["value"] == "authenticator"

    chosen = choose_the_authenticator(client)
    verify = form_of(chosen, "two_factor_verify_code_form")
    assert verify["action"] == "/auth/tf-validate"  # not signed in: the session carries the state
    done = client.post(verify["action"], data={"code": pyotp.TOTP(key_of(chosen)).now()})
    assert done.status_code == 302
    with client.session_transaction() as state:
        assert state["_user_id"] == user.fs_uniquifier


def test_a_wrong_code_at_the_first_sign_in_says_so_and_offers_to_start_again(
    client: FlaskClient, db_session: Session
) -> None:
    first_sign_in(client, db_session)
    choose_the_authenticator(client)
    response = client.post("/auth/tf-validate", data={"code": "123456"})
    body = body_of(response)

    assert response.status_code == 200 and body.count(WRONG_CODE) == 1
    assert "<h1>Set up two-factor authentication</h1>" in body
    assert "Enter the code that your authenticator app shows to finish the setup." in body
    assert re.search(r'<a class="link" href="/auth/tf-setup">Start again</a>', body)
    assert LOST_AUTHENTICATOR not in body  # there is no authenticator to lose yet
    assert attributes(tag_named(body, "code"))["value"] == ""


# ------------------------------------------------------------------------------ the words


@pytest.mark.parametrize(("key", "message"), MESSAGES.items())
def test_the_messages_of_these_pages_are_the_applications_own(
    app: Flask, key: str, message: tuple[str, str]
) -> None:
    assert app.config[f"SECURITY_MSG_{key}"] == message
