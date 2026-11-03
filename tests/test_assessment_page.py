"""The assessment page: where it says it is, times that stay whole, and tables that keep what
matters readable (the hostname on a narrow screen, the result of a domain check on a phone).
"""

from __future__ import annotations

import re

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models import Assessment, User
from app.models.base import utc_now
from tests.helpers import attributes, link_texts, login_as, nav_html
from tests.test_summary import evaluated

MOMENT = (
    r'<time datetime="[^"]+"><span class="whitespace-nowrap">\d{4}-\d{2}-\d{2}</span> '
    r'<span class="whitespace-nowrap">\d{2}:\d{2} UTC</span></time>'
)
PLAIN_MOMENT = r'<time datetime="[^"]+">\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC</time>'


def finished_scan_page(client: FlaskClient, session: Session, *, archived: bool = False) -> str:
    """The page of an assessment with a finished scan, its hosts, findings and domain checks."""
    scan, _rows = evaluated(session, "vendor.example")
    owner = session.get(User, scan.requested_by)
    assert owner is not None
    login_as(client, owner)
    assessment: Assessment = scan.assessment
    if archived:
        assessment.archived_at = utc_now()
        session.commit()
    response = client.get(f"/assessments/{assessment.id}")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def section(page: str, title: str) -> str:
    """What follows the <h2> that starts with this title (enough of it for the panel's table)."""
    heading = re.search(rf"<h2[^>]*>{re.escape(title)}", page)
    assert heading is not None, title
    return page[heading.start() : heading.start() + 9000]


def test_the_page_names_its_parent_in_the_top_bar_and_has_no_back_link_of_its_own(
    client: FlaskClient, db_session: Session
) -> None:
    page = finished_scan_page(client, db_session)

    trail = nav_html(page, "Breadcrumb")
    assert link_texts(trail) == ["Assessments"]
    assert attributes(re.findall(r"<a [^>]*>", trail)[0])["href"] == "/assessments/"
    main = re.search(r"<main[^>]*>(.*?)</main>", page, re.S)
    assert main is not None
    content = main.group(1)
    assert 'href="/assessments/"' not in content  # the bar says it; the page does not repeat it


def test_every_time_on_the_page_stays_whole(client: FlaskClient, db_session: Session) -> None:
    page = finished_scan_page(client, db_session)

    assert len(re.findall(MOMENT, page)) == 2  # created, in the heading, and queued, in the scan
    assert not re.findall(PLAIN_MOMENT, page)
    assert re.search(
        r'<time datetime="[^"]+" class="whitespace-nowrap">\d{2}:\d{2}:\d{2} UTC</time>', page
    )  # when the scan finished


def test_an_archived_assessment_gives_the_time_it_was_archived_as_a_moment(
    client: FlaskClient, db_session: Session
) -> None:
    page = finished_scan_page(client, db_session, archived=True)

    assert len(re.findall(MOMENT, page)) == 3  # and the time of archiving, in the notice
    assert not re.findall(PLAIN_MOMENT, page)


def test_the_hosts_table_gives_the_hostname_room_and_trims_the_sides_of_the_cells(
    client: FlaskClient, db_session: Session
) -> None:
    page = finished_scan_page(client, db_session)

    panel = section(page, "Hosts")
    table = re.search(r"<table [^>]*>", panel)
    assert (
        table is not None and attributes(table.group(0))["class"] == "data-table data-table-dense"
    )
    assert '<th scope="col" class="min-w-48">Hostname</th>' in panel
    other = re.search(r"<table [^>]*>", section(page, "Domain checks"))
    assert other is not None and attributes(other.group(0))["class"] == "data-table"


def test_a_long_result_of_a_domain_check_may_wrap_on_a_phone(
    client: FlaskClient, db_session: Session
) -> None:
    page = finished_scan_page(client, db_session)

    checks = section(page, "Domain checks")
    cells = re.findall(r'<td class="max-sm:\[&_\.badge\]:whitespace-normal">', checks)
    assert len(cells) == 3  # email, registration and security.txt in this scan
