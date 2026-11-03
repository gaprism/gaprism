"""The page that asks before an assessment is deleted: where it says it is, what it counts, and a
confirmation field that is marked when it was refused."""

from __future__ import annotations

import re

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models import Assessment, User
from tests.helpers import attributes, link_texts, login_as, nav_html
from tests.test_summary import evaluated


def owned(client: FlaskClient, session: Session) -> Assessment:
    scan, _rows = evaluated(session, "vendor.example")
    user = session.get(User, scan.requested_by)
    assert user is not None
    login_as(client, user)
    return scan.assessment


def content_of(page: str) -> str:
    main = re.search(r"<main[^>]*>(.*?)</main>", page, re.S)
    assert main is not None
    return main.group(1)


def test_the_page_names_its_parents_in_the_top_bar_and_has_no_trail_of_its_own(
    client: FlaskClient, db_session: Session
) -> None:
    assessment = owned(client, db_session)
    page = client.get(f"/assessments/{assessment.id}/delete").get_data(as_text=True)

    trail = nav_html(page, "Breadcrumb")
    assert link_texts(trail) == ["Assessments", "vendor.example"]
    hrefs = [attributes(tag)["href"] for tag in re.findall(r"<a [^>]*>", trail)]
    assert hrefs == ["/assessments/", f"/assessments/{assessment.id}"]
    assert "Where you are" not in page
    assert link_texts(content_of(page)) == ["Cancel"]  # the bar says where; the page asks


def test_the_counts_are_set_in_line_with_their_labels(
    client: FlaskClient, db_session: Session
) -> None:
    """A figure under its label's baseline reads as if it belonged to the next row."""
    assessment = owned(client, db_session)
    page = client.get(f"/assessments/{assessment.id}/delete").get_data(as_text=True)

    counts = re.search(r"<dl [^>]*>(.*?)</dl>", page, re.S)
    assert counts is not None
    assert len(re.findall(r'<dd class="mt-0">', counts.group(1))) == 4  # scans to decisions


def test_a_refused_confirmation_is_marked_by_the_stylesheets_rule(
    client: FlaskClient, db_session: Session
) -> None:
    """The field has no border colour of its own: a utility class would beat the rule that
    gives a refused field its red border (assets/app.css, base layer)."""
    assessment = owned(client, db_session)
    page = client.post(
        f"/assessments/{assessment.id}/delete", data={"confirm": "not the domain"}
    ).get_data(as_text=True)

    tag = re.search(r'<input [^>]*\bid="confirm"[^>]*>', page)
    assert tag is not None
    field = attributes(tag.group(0))
    assert field["aria-invalid"] == "true"
    assert "border" not in field["class"].split()
    assert not [name for name in field["class"].split() if name.startswith("border-")]
