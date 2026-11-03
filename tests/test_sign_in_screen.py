"""The sign-in screen: the page, its second step and what it says when something goes wrong.

Flask-Security-Too does the work (the checks, the session, the second factor). The pages are the
application's own markup for it, in the voice of the brand: sentence case, and for a problem what
happened and what to do. What the forms post is unchanged; tests/auth keep the behaviour.
"""

from __future__ import annotations

import re

from flask.testing import FlaskClient
from flask_security.utils import hash_password
from sqlalchemy.orm import Session

from app.extensions import security
from app.models.auth import User
from tests.helpers import attributes, make_app

PASSWORD = "Correct-Horse-Battery-1"
FAILED = "The email address or password is not correct. Check them and try again."
WRONG_CODE = (
    "The code is not correct or has expired. Enter the current code from your authenticator app."
)
EXPIRED = "The sign-in has expired. Enter your email address and password again."
LOST_AUTHENTICATOR = "Lost your authenticator? Ask an administrator to reset it."
# What the library says by itself, which is neither the voice of the brand nor, for the rescue
# form, something that can work: the application has no mail server.
LIBRARY_WORDING = (
    "Login",
    "Email Address",
    "Remember Me",
    "Authentication failed",
    "do not have permissions",
    "Two-Factor Authentication",
    "Authentication Code",
    "Submit Code",
    "Invalid code",
)
RESCUE = ("tf-rescue", "Contact Administrator", "Send code via email", "Trouble Accessing")


def make_user(session: Session, *, authenticator: bool = False) -> User:
    user = User(email="analyst@example.org", password=hash_password(PASSWORD), active=True)
    if authenticator:
        user.tf_primary_method = "authenticator"
        user.tf_totp_secret = security._totp_factory.generate_totp_secret()
    session.add(user)
    session.commit()
    return user


def sign_in_with_password(client: FlaskClient, user: User) -> None:
    response = client.post("/auth/login", data={"email": user.email, "password": PASSWORD})
    assert response.status_code == 302 and "/auth/tf-validate" in response.headers["Location"]


def body_of(response: object) -> str:
    return response.get_data(as_text=True)  # type: ignore[attr-defined,no-any-return]


def tag_named(body: str, name: str) -> str:
    """The one <input> of the page with this name."""
    tags = [
        tag for tag in re.findall(r"<input [^>]*>", body) if attributes(tag).get("name") == name
    ]
    assert len(tags) == 1, f"{len(tags)} inputs named {name}"
    return tags[0]


def labels(body: str) -> list[str]:
    return re.findall(r"<label[^>]*>.*?</label>", body, re.S)


def test_the_sign_in_page_is_in_sentence_case(client: FlaskClient) -> None:
    response = client.get("/auth/login")
    body = body_of(response)
    assert response.status_code == 200
    assert "<title>Sign in · Gaprism</title>" in body
    assert "<h1>Sign in</h1>" in body
    assert '<label for="email">Email address</label>' in body
    assert '<label for="password">Password</label>' in body
    remember = [label for label in labels(body) if 'name="remember"' in label]
    assert len(remember) == 1 and "Remember me" in remember[0]  # the words tick the box too
    assert re.search(r'<button[^>]*type="submit"[^>]*>Sign in</button>', body)
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def test_the_sign_in_form_posts_what_the_login_needs(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    body = body_of(app.test_client().get("/auth/login?next=/assessments/"))

    form = re.search(r'<form [^>]*name="login_user_form"[^>]*>', body)
    assert form is not None
    assert attributes(form.group(0))["action"] == "/auth/login?next=/assessments/"
    assert attributes(form.group(0))["method"] == "post"
    assert attributes(tag_named(body, "csrf_token"))["type"] == "hidden"
    assert attributes(tag_named(body, "csrf_token"))["value"]
    email, password = tag_named(body, "email"), tag_named(body, "password")
    assert (attributes(email)["type"], attributes(email)["autocomplete"]) == ("email", "email")
    assert (attributes(password)["type"], attributes(password)["autocomplete"]) == (
        "password",
        "current-password",
    )
    assert " required" in email and " required" in password
    assert attributes(tag_named(body, "remember"))["type"] == "checkbox"


def test_a_failed_sign_in_says_what_happened_and_what_to_do(
    client: FlaskClient, db_session: Session
) -> None:
    user = make_user(db_session)
    response = client.post("/auth/login", data={"email": user.email, "password": "wrong"})
    body = body_of(response)

    assert response.status_code == 200 and body.count(FAILED) == 1
    assert re.search(rf'<div class="notice[^"]*" role="alert">.*?{re.escape(FAILED)}', body, re.S)
    assert attributes(tag_named(body, "email"))["value"] == user.email  # the address is kept
    assert attributes(tag_named(body, "password")).get("value", "") == ""  # the password is not
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording


def test_a_second_step_that_was_not_started_sends_back_to_the_sign_in(client: FlaskClient) -> None:
    body = body_of(client.post("/auth/tf-validate", data={"code": "000000"}, follow_redirects=True))
    assert "<h1>Sign in</h1>" in body and body.count(EXPIRED) == 1
    assert "do not have permissions" not in body


def test_the_second_step_asks_for_the_code_and_offers_no_rescue_that_cannot_work(
    client: FlaskClient, db_session: Session
) -> None:
    sign_in_with_password(client, make_user(db_session, authenticator=True))
    response = client.get("/auth/tf-validate")
    body = body_of(response)

    assert response.status_code == 200
    assert "<title>Two-factor authentication · Gaprism</title>" in body
    assert "<h1>Two-factor authentication</h1>" in body
    assert "Enter the code from your authenticator app." in body
    assert '<label for="code">Authentication code</label>' in body
    code = attributes(tag_named(body, "code"))
    assert code["autocomplete"] == "one-time-code" and code["inputmode"] == "numeric"
    assert " required" in tag_named(body, "code")
    assert re.search(r'<button[^>]*type="submit"[^>]*>Verify code</button>', body)
    assert LOST_AUTHENTICATOR in body
    for gone in (*RESCUE, *LIBRARY_WORDING):
        assert gone not in body, gone


def test_a_wrong_code_says_what_happened_and_is_not_kept(
    client: FlaskClient, db_session: Session
) -> None:
    sign_in_with_password(client, make_user(db_session, authenticator=True))
    response = client.post("/auth/tf-validate", data={"code": "123456"})
    body = body_of(response)

    assert response.status_code == 200 and body.count(WRONG_CODE) == 1
    assert re.search(
        rf'<p class="text-sm text-danger" id="code-error">{re.escape(WRONG_CODE)}</p>', body
    )
    assert attributes(tag_named(body, "code"))["value"] == ""  # a wrong code is no use again
    assert "<h1>Two-factor authentication</h1>" in body and LOST_AUTHENTICATOR in body
    for wording in LIBRARY_WORDING:
        assert wording not in body, wording
