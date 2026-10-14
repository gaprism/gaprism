"""S1.1: creating an assessment from a domain name."""

import pytest
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
from tests.helpers import create_assessment as persist_assessment
from tests.helpers import create_user, login_as, make_app


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
        ("https://vendor.example.com/login", "URL schemes"),
        ("vendor.example.com:8443", "Port numbers"),
        ("203.0.113.7", "IP address literals"),
        ("*.vendor.example.com", "Wildcard"),
        ("co.kr", "public suffix"),
        ("blogspot.com", "public suffix"),
        ("com", "public suffix"),
        ("", "required"),
    ],
)
def test_invalid_domains_are_refused_with_a_reason(
    client: FlaskClient, db_session: Session, entered: str, message: str
) -> None:
    login_as(client, create_user(db_session))

    response = client.post("/assessments/new", data={"domain": entered, "visibility": "private"})
    assert response.status_code == 200
    assert message in response.get_data(as_text=True)
    assert _count(db_session) == 0


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
    assert "already exists" in page
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
        with pytest.raises(ScopeValidationError, match="blocklist"):
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
