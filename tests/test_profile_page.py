"""The profile page: a signed-in person keeps their own name, and the interface shows it.

Everything the page decides is the service's work (tests/test_profile_service.py); here are the
door, the form, the words and the places where the name appears.
"""

from __future__ import annotations

import re

import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_security import url_for_security
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, User
from tests.helpers import Marked, attributes, audit_rows, create_user, login_as, make_app
from tests.test_profile_service import NAME_CHARACTER, NAME_TOO_LONG

REFUSALS = [
    ("B" * 101, NAME_TOO_LONG),
    ("Anna\N{RIGHT-TO-LEFT OVERRIDE}Meier", NAME_CHARACTER),
]


def html(response: object) -> str:
    return response.get_data(as_text=True)  # type: ignore[attr-defined,no-any-return]


def signed_in(client: FlaskClient, session: Session, **fields: str) -> User:
    user = create_user(session, fields.pop("email", None))
    for field, value in fields.items():
        setattr(user, field, value)
    session.commit()
    login_as(client, user)
    return user


def avatar(page: str) -> str:
    found = re.search(r'<span class="avatar"[^>]*>(.*?)</span>', page, re.DOTALL)
    assert found, "the page has no avatar"
    return found.group(1).strip()


def menu(page: str) -> str:
    found = re.search(r'<ul id="account-menu"[^>]*>(.*?)</ul>', page, re.DOTALL)
    assert found, "the page has no account menu"
    return found.group(1)


# ------------------------------------------------------------------------------ the door


def test_the_page_is_for_somebody_who_is_signed_in(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    rules = [rule for rule in app.url_map.iter_rules() if rule.endpoint.startswith("profile.")]
    assert {rule.endpoint for rule in rules} == {"profile.index"}  # a new route needs a test here
    for rule in rules:
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = client.open(rule.rule, method=method, data={"name": "Eve"})
            assert response.status_code == 302, method
            assert "/auth/login" in response.headers["Location"]
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_the_form_needs_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        session = db.session()
        user = create_user(session)
        try:
            client = app.test_client()
            login_as(client, user)
            assert client.post("/profile/", data={"name": "Eve"}).status_code == 400
            session.refresh(user)
            assert user.name is None
        finally:
            session.delete(user)
            session.commit()


# ------------------------------------------------------------------------------ the form


def test_the_page_shows_the_address_and_the_name_the_person_has(
    client: FlaskClient, db_session: Session, app: Flask
) -> None:
    signed_in(client, db_session, email="anna@example.org", name="Anna Meier")
    page = html(client.get("/profile/"))

    assert "<h1>Profile</h1>" in page and "<bdi>anna@example.org</bdi>" in page
    assert 'name="email"' not in page  # the address is shown, not edited here
    tag = re.search(r'<input [^>]*\bid="name"[^>]*>', page)
    assert tag is not None and attributes(tag.group(0))["value"] == "Anna Meier"
    with app.test_request_context():
        for endpoint in ("change_password", "two_factor_setup"):
            assert f'href="{url_for_security(endpoint)}"' in page, endpoint


def test_the_input_tells_the_browser_what_it_may_do(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session)
    tag = re.search(r'<input [^>]*\bid="name"[^>]*>', html(client.get("/profile/")))
    assert tag is not None
    fields = attributes(tag.group(0))
    assert fields["maxlength"] == "100" and fields["autocomplete"] == "name"
    assert " required" not in tag.group(0)  # a name is optional


def test_saving_stores_the_cleaned_name_audits_it_and_says_so(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    response = client.post("/profile/", data={"name": "  Anna   Meier "}, follow_redirects=True)
    page = html(response)

    assert response.request.path == "/profile/" and "Profile saved." in page
    db_session.refresh(user)
    assert user.name == "Anna Meier"
    tag = re.search(r'<input [^>]*\bid="name"[^>]*>', page)
    assert tag is not None and attributes(tag.group(0))["value"] == "Anna Meier"

    (event,) = audit_rows(db_session, "user.profile_changed")
    assert (event.source, event.actor_id, event.actor_email) == ("web", user.id, user.email)
    assert event.details == {"email": user.email, "name": "set"}


def test_an_empty_name_takes_the_name_away(client: FlaskClient, db_session: Session) -> None:
    user = signed_in(client, db_session, name="Anna Meier")
    client.post("/profile/", data={"name": "   "})
    db_session.refresh(user)
    assert user.name is None
    assert audit_rows(db_session, "user.profile_changed")[-1].details["name"] == "cleared"


def test_saving_the_same_name_says_so_and_writes_nothing_to_the_log(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session, name="Anna Meier")
    page = html(client.post("/profile/", data={"name": "Anna Meier"}, follow_redirects=True))
    assert "Profile saved." in page
    assert audit_rows(db_session, "user.profile_changed") == []


@pytest.mark.parametrize(("entered", "message"), REFUSALS)
def test_a_refused_name_says_what_to_do_and_the_old_name_stays(
    client: FlaskClient, db_session: Session, entered: str, message: str
) -> None:
    user = signed_in(client, db_session, name="Anna Meier")
    response = client.post("/profile/", data={"name": entered})

    assert response.status_code == 200  # the form again, with its error
    assert f'id="name-error">{message}</p>' in html(response)
    assert "Profile saved." not in html(response)
    db_session.refresh(user)
    assert user.name == "Anna Meier"
    assert audit_rows(db_session, "user.profile_changed") == []


def test_every_refusal_is_translated_when_it_is_shown(
    client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in(client, db_session)
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    for entered, message in REFUSALS:
        page = html(client.post("/profile/", data={"name": entered}))
        assert f'id="name-error">[xx] {message}</p>' in page, message
    assert "[xx] Profile" in html(client.get("/profile/"))


# ------------------------------------------------------------------------------ where it shows


def test_the_menu_and_the_avatar_go_by_the_name_when_there_is_one(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session, email="anna.meier@example.org")
    plain = html(client.get("/assessments/"))
    assert avatar(plain) == "AM" and "<bdi>" not in menu(plain)  # the address, as before
    assert "anna.meier@example.org" in menu(plain)

    user.name = "Zoe Keller"
    db_session.commit()
    named = html(client.get("/assessments/"))
    assert avatar(named) == "ZK"
    assert "<bdi>Zoe Keller</bdi>" in menu(named) and "anna.meier@example.org" in menu(named)


def test_the_menu_leads_to_the_profile_before_the_password(
    client: FlaskClient, db_session: Session, app: Flask
) -> None:
    signed_in(client, db_session)
    items = menu(html(client.get("/assessments/")))
    with app.test_request_context():
        password = url_for_security("change_password")
    assert 'href="/profile/"' in items and items.index('href="/profile/"') < items.index(password)


def test_a_name_is_shown_escaped(client: FlaskClient, db_session: Session) -> None:
    signed_in(client, db_session, name="<script>alert(1)</script>")
    for url in ("/assessments/", "/profile/"):
        page = html(client.get(url))
        assert "<script>alert(1)</script>" not in page, url
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page, url
