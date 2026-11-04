"""S1.1: creating an assessment from a domain name."""

import re
from gettext import NullTranslations

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Assessment
from app.service.assessments import (
    DuplicateAssessmentError,
    create_assessment,
)
from app.service.discovery.scope import ScopeValidationError
from app.service.users import create_admin
from tests.discovery.test_scope import EMPTY, IP_ADDRESS, PORT, SCHEME, WILDCARD, suffix
from tests.helpers import attributes, create_user, login_as, make_app
from tests.helpers import create_assessment as persist_assessment

DOMAIN_TOO_LONG = "A domain name has at most 253 characters. Check what you entered."
LABEL_TOO_LONG = "The label has more than 255 characters. Shorten it."
VISIBILITY = "Choose who can see the assessment."
DUPLICATE = "This domain already has an assessment. Open that one instead."
BLOCKED = (
    "This installation does not assess this domain: it is on the list of blocked domains. "
    "Ask an administrator if that is a mistake."
)
# What the library's validators say by themselves.
LIBRARY_WORDING = ("This field is required", "Field cannot be longer", "Not a valid choice")


def _count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(Assessment)) or 0


def test_new_assessment_page_requires_sign_in(client: FlaskClient) -> None:
    for method in (client.get, client.post):
        response = method("/assessments/new")
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


def test_the_form_offers_private_and_shared(client: FlaskClient, db_session: Session) -> None:
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    assert 'value="private"' in page and 'value="shared"' in page
    assert "Only me" in page and "Everyone here" in page
    assert 'value="team"' not in page and "The whole team" not in page


def test_the_form_refuses_the_retired_name_team(client: FlaskClient, db_session: Session) -> None:
    login_as(client, create_user(db_session))
    response = client.post(
        "/assessments/new", data={"domain": "retired.example", "visibility": "team"}
    )
    assert response.status_code == 200  # the form again, with its error
    assert _count(db_session) == 0


def test_create_assessment_with_defaults(client: FlaskClient, db_session: Session) -> None:
    user = create_user(db_session)
    login_as(client, user)

    response = client.post(
        "/assessments/new",
        data={
            "domain": "  Vendor.Example.COM.  ",
            "label": "Payroll vendor",
            "visibility": "private",
        },
    )
    assert response.status_code == 302

    created = db_session.scalars(select(Assessment)).one()
    assert (created.domain, created.domain_display) == ("vendor.example.com", "vendor.example.com")
    assert created.label == "Payroll vendor"
    assert created.visibility == "private"
    assert created.created_by == user.id

    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    page = detail.get_data(as_text=True)
    assert "vendor.example.com" in page and "Payroll vendor" in page
    assert "Assessment created." in page


def test_internationalised_domains_are_stored_as_punycode(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))
    client.post("/assessments/new", data={"domain": "münchen.de", "visibility": "shared"})

    created = db_session.scalars(select(Assessment)).one()
    assert created.domain == "xn--mnchen-3ya.de"
    assert created.domain_display == "münchen.de"
    assert created.visibility == "shared"


@pytest.mark.parametrize(
    ("entered", "message"),
    [
        ("https://vendor.example.com/login", SCHEME),
        ("vendor.example.com:8443", PORT),
        ("203.0.113.7", IP_ADDRESS),
        ("*.vendor.example.com", WILDCARD),
        ("co.kr", suffix("co.kr")),
        ("blogspot.com", suffix("blogspot.com")),
        ("com", suffix("com")),
        ("", EMPTY),
    ],
)
def test_invalid_domains_are_refused_with_a_reason(
    client: FlaskClient, db_session: Session, entered: str, message: str
) -> None:
    login_as(client, create_user(db_session))

    response = client.post("/assessments/new", data={"domain": entered, "visibility": "private"})
    assert response.status_code == 200
    assert f'id="domain-error">{message}</p>' in response.get_data(as_text=True)
    assert _count(db_session) == 0


def post_form(client: FlaskClient, **data: str) -> str:
    return client.post("/assessments/new", data=data).get_data(as_text=True)


def test_the_form_refuses_in_our_words_and_keeps_what_its_fields_tell_the_browser(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))

    page = post_form(client, domain="a" * 254, label="x" * 256, visibility="team")
    assert f'id="domain-error">{DOMAIN_TOO_LONG}</p>' in page
    assert f'id="label-error">{LABEL_TOO_LONG}</p>' in page
    assert VISIBILITY in page
    assert EMPTY in post_form(client, domain="   ")
    for wording in LIBRARY_WORDING:
        assert wording not in page, wording
    domain = re.search(r'<input [^>]*\bid="domain"[^>]*>', page)
    label = re.search(r'<input [^>]*\bid="label"[^>]*>', page)
    assert domain is not None and label is not None
    assert attributes(domain.group(0))["maxlength"] == "253" and " required" in domain.group(0)
    assert attributes(label.group(0))["maxlength"] == "255"
    assert _count(db_session) == 0


def test_a_blocked_domain_is_refused_and_the_person_is_told_what_to_do(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "BLOCKED_DOMAINS", ["corp.example"])
    login_as(client, create_user(db_session))
    page = post_form(client, domain="intranet.corp.example", visibility="private")
    assert f'id="domain-error">{BLOCKED}</p>' in page
    assert _count(db_session) == 0


class Marked(NullTranslations):
    """A language in which every sentence starts with its code: proof that a text went through
    gettext, at the time it is shown and not when the module was loaded."""

    def gettext(self, message: str) -> str:
        return f"[xx] {message}"

    def ngettext(self, singular: str, plural: str, n: int) -> str:
        return f"[xx] {singular if n == 1 else plural}"


def test_every_refusal_of_the_form_is_translated_when_it_is_shown(
    client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = create_user(db_session)
    persist_assessment(db_session, owner, "taken.example", "shared")
    login_as(client, create_user(db_session))
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())

    assert f"[xx] {SCHEME}" in post_form(client, domain="https://vendor.example")
    assert f"[xx] {suffix('com')}" in post_form(client, domain="com")  # the part is filled in last
    assert f"[xx] {EMPTY}" in post_form(client, domain="")
    assert f"[xx] {DOMAIN_TOO_LONG}" in post_form(client, domain="a" * 254)
    assert f"[xx] {LABEL_TOO_LONG}" in post_form(client, domain="vendor.example", label="x" * 256)
    assert f"[xx] {VISIBILITY}" in post_form(client, domain="vendor.example", visibility="team")
    assert f"[xx] {DUPLICATE}" in post_form(client, domain="taken.example")


def test_the_same_domain_cannot_be_created_twice_by_someone_who_can_see_it(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    colleague = create_user(db_session)
    existing = persist_assessment(db_session, owner, "vendor.example.com", "shared")
    login_as(client, colleague)

    response = client.post("/assessments/new", data={"domain": "vendor.example.com"})
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "already exists" in page  # the notice, with the link
    assert f'id="domain-error">{DUPLICATE}</p>' in page  # and the field says what to do
    assert f"/assessments/{existing.id}" in page  # links to the existing one
    assert _count(db_session) == 1


def test_a_private_assessment_of_someone_else_does_not_block_a_new_one(
    db_session: Session,
) -> None:
    """Existence of an assessment the user cannot see must not be revealed."""
    owner = create_user(db_session)
    other = create_user(db_session)
    persist_assessment(db_session, owner, "vendor.example.com", "private")

    created = create_assessment(db_session, other, "vendor.example.com")
    assert created.created_by == other.id


def test_blocked_domains_and_everything_below_them_are_refused(db_session: Session) -> None:
    user = create_user(db_session)
    for entered in ("corp.example", "intranet.corp.example"):
        with pytest.raises(ScopeValidationError, match="blocked domains"):
            create_assessment(db_session, user, entered, blocked_domains=["corp.example"])
    create_assessment(db_session, user, "notcorp.example", blocked_domains=["corp.example"])


def test_service_rejects_unknown_visibility_and_overlong_labels(db_session: Session) -> None:
    user = create_user(db_session)
    for unknown in ("public", "team"):  # "team" is the retired name of "shared"
        with pytest.raises(ValueError, match="visibility"):
            create_assessment(db_session, user, "a.example.com", visibility=unknown)
    with pytest.raises(ValueError, match="label"):
        create_assessment(db_session, user, "b.example.com", label="x" * 256)
    assert _count(db_session) == 0


def test_duplicate_error_carries_the_existing_assessment(db_session: Session) -> None:
    user = create_user(db_session)
    first = persist_assessment(db_session, user, "vendor.example.com")
    with pytest.raises(DuplicateAssessmentError) as raised:
        create_assessment(db_session, user, "VENDOR.example.com")
    assert raised.value.existing.id == first.id


def test_detail_follows_the_visibility_rules(client: FlaskClient, db_session: Session) -> None:
    owner = create_user(db_session)
    colleague = create_user(db_session)
    admin = create_admin(db_session, "boss@example.org", "Administrator-Pass-1")
    db_session.commit()
    private = persist_assessment(db_session, owner, "private.example.com", "private")
    shared = persist_assessment(db_session, owner, "shared.example.com", "shared")

    login_as(client, colleague)
    assert client.get(f"/assessments/{shared.id}").status_code == 200
    # 404, not 403: a private assessment must not even be confirmed to exist.
    assert client.get(f"/assessments/{private.id}").status_code == 404

    login_as(client, admin)
    assert client.get(f"/assessments/{private.id}").status_code == 200
    assert client.get("/assessments/00000000-0000-0000-0000-000000000000").status_code == 404


def test_creating_an_assessment_needs_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        user = create_user(db.session())
        client = app.test_client()
        login_as(client, user)
        response = client.post("/assessments/new", data={"domain": "vendor.example.com"})
        assert response.status_code == 400
        db.session.delete(user)
        db.session.commit()
