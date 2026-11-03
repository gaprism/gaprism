"""The assessment list: tabs for the live and the archived, dates that never break inside
themselves, and the columns a phone keeps (the domain with its label under it, and not the owner).
"""

from __future__ import annotations

import re

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models import Assessment
from app.service import assessments as assessment_service
from tests.helpers import (
    attributes,
    create_assessment,
    create_user,
    link_texts,
    login_as,
    nav_html,
)

TABS = "Which assessments to show"
MOMENT = (
    r'<time datetime="[^"]+"><span class="whitespace-nowrap">\d{4}-\d{2}-\d{2}</span> '
    r'<span class="whitespace-nowrap">\d{2}:\d{2} UTC</span></time>'
)


def listing(client: FlaskClient, view: str = "") -> str:
    response = client.get("/assessments/" + (f"?view={view}" if view else ""))
    assert response.status_code == 200
    return response.get_data(as_text=True)


def signed_in_with_three(client: FlaskClient, session: Session) -> Assessment:
    """Two live assessments (one with a label) and one archived; returns the labelled one."""
    owner = create_user(session)
    create_assessment(session, owner, "live-one.example")
    labelled = create_assessment(session, owner, "labelled.example")
    labelled.label = "Annual review"
    old = create_assessment(session, owner, "old.example")
    session.commit()
    assessment_service.archive(session, old, owner)
    session.commit()
    login_as(client, owner)
    return labelled


def row_of(body: str, domain: str) -> str:
    rows = [row for row in re.findall(r"<tr>.*?</tr>", body, re.S) if domain in row]
    assert len(rows) == 1, domain
    return rows[0]


def test_the_list_switches_between_the_live_and_the_archived_with_tabs(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_with_three(client, db_session)

    tabs = nav_html(listing(client), TABS)
    assert link_texts(tabs) == ["Active (2)", "Archived (1)"]
    links = [attributes(tag) for tag in re.findall(r"<a [^>]*>", tabs)]
    assert [link["class"] for link in links] == ["tab", "tab"]  # the tabs of the findings page
    assert [link["href"] for link in links] == ["/assessments/", "/assessments/?view=archived"]
    assert ["aria-current" in link for link in links] == [True, False]

    on_archive = nav_html(listing(client, "archived"), TABS)
    links = [attributes(tag) for tag in re.findall(r"<a [^>]*>", on_archive)]
    assert ["aria-current" in link for link in links] == [False, True]


def test_a_date_never_breaks_inside_itself_and_stays_whole_beyond_a_phone(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_with_three(client, db_session)

    for body, expected in ((listing(client), 2), (listing(client, "archived"), 2)):
        # the live view: the created date of two rows; the archive: created and archived of one
        assert len(re.findall(MOMENT, body)) == expected
        cells = re.findall(r'<td class="sm:whitespace-nowrap"><time', body)
        assert len(cells) == expected  # one line from 640 px up, between date and time below


def test_a_phone_keeps_the_domain_with_its_label_and_leaves_the_owner_out(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_with_three(client, db_session)
    body = listing(client)

    for title in ("Label", "Owner"):
        assert f'<th scope="col" class="hidden sm:table-cell">{title}</th>' in body
    for title in ("Domain", "Visibility", "Created"):
        assert f'<th scope="col">{title}</th>' in body

    labelled = row_of(body, "labelled.example")
    assert '<p class="mt-1 text-xs text-muted sm:hidden">Annual review</p>' in labelled
    assert '<td class="hidden sm:table-cell">Annual review</td>' in labelled
    plain = row_of(body, "live-one.example")
    assert "sm:hidden" not in plain and '<td class="hidden sm:table-cell">—</td>' in plain


def test_the_domain_is_the_link_and_is_set_in_the_technical_face(
    client: FlaskClient, db_session: Session
) -> None:
    labelled = signed_in_with_three(client, db_session)
    row = row_of(listing(client), "labelled.example")
    assert (
        f'<a class="link" href="/assessments/{labelled.id}"><bdi class="font-mono">'
        "labelled.example</bdi></a>"
    ) in row
