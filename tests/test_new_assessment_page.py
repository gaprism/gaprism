"""The new-assessment form: where it says it is, and a domain field that the phone leaves alone."""

from __future__ import annotations

import re

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from tests.helpers import attributes, create_assessment, create_user, link_texts, login_as, nav_html


def signed_in_page(client: FlaskClient, session: Session, **form: str) -> str:
    """The form as a signed-in user gets it: empty, or again after sending ``form``."""
    login_as(client, create_user(session))
    response = (
        client.post("/assessments/new", data=form) if form else client.get("/assessments/new")
    )
    assert response.status_code == 200
    return response.get_data(as_text=True)


def content_of(page: str) -> str:
    main = re.search(r"<main[^>]*>(.*?)</main>", page, re.S)
    assert main is not None
    return main.group(1)


def test_the_page_names_its_parent_in_the_top_bar_and_has_no_back_link_of_its_own(
    client: FlaskClient, db_session: Session
) -> None:
    page = signed_in_page(client, db_session)

    trail = nav_html(page, "Breadcrumb")
    assert link_texts(trail) == ["Assessments"]
    assert attributes(re.findall(r"<a [^>]*>", trail)[0])["href"] == "/assessments/"
    # the bar says it; the page does not repeat it
    assert link_texts(content_of(page)) == ["Cancel"]


def test_the_form_says_where_it_is_after_a_refusal_too(
    client: FlaskClient, db_session: Session
) -> None:
    refused = signed_in_page(client, db_session, domain="https://vendor.example.com/login")
    assert link_texts(nav_html(refused, "Breadcrumb")) == ["Assessments"]
    assert "Assessments" not in link_texts(content_of(refused))

    owner = create_user(db_session)
    create_assessment(db_session, owner, "taken.example", "shared")
    duplicate = signed_in_page(client, db_session, domain="taken.example")
    assert link_texts(nav_html(duplicate, "Breadcrumb")) == ["Assessments"]
    assert link_texts(content_of(duplicate)) == ["taken.example", "Cancel"]  # the existing one


def test_the_domain_is_left_as_typed_by_the_phone(client: FlaskClient, db_session: Session) -> None:
    """A mistyped vendor domain would be assessed as if it were the right one: the keyboard
    must not capitalise it or correct it to a word, as the delete form's field does not either."""
    page = signed_in_page(client, db_session)

    tag = re.search(r'<input [^>]*\bid="domain"[^>]*>', page)
    assert tag is not None
    field = attributes(tag.group(0))
    assert field["autocapitalize"] == "off" and field["spellcheck"] == "false"
    assert field["autocomplete"] == "off"
