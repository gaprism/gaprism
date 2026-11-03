"""The pages below an assessment (scan history, comparison, findings, host, domain): times that stay
whole, and tables and sections that keep to the width of a phone."""

from __future__ import annotations

import re

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Host, User
from tests.helpers import login_as
from tests.test_history import Two, two_scans
from tests.test_summary import evaluated

MOMENT = (
    r'<time datetime="[^"]+"><span class="whitespace-nowrap">\d{4}-\d{2}-\d{2}</span> '
    r'<span class="whitespace-nowrap">\d{2}:\d{2} UTC</span></time>'
)
PLAIN_MOMENT = r'<time datetime="[^"]+">\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC</time>'
CHECK_HEAD = (
    r'<div class="flex flex-wrap items-center gap-3 max-sm:\[&_\.badge\]:whitespace-normal">'
)


@pytest.fixture
def two(client: FlaskClient, db_session: Session) -> Two:
    scans = two_scans(db_session)
    login_as(client, scans.user)
    return scans


@pytest.fixture
def vendor(client: FlaskClient, db_session: Session) -> Assessment:
    """An assessment with one finished scan: four hosts, their findings, the domain checks."""
    scan, _rows = evaluated(db_session, "vendor.example")
    user = db_session.get(User, scan.requested_by)
    assert user is not None
    login_as(client, user)
    return scan.assessment


def page(client: FlaskClient, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, url
    return response.get_data(as_text=True)


def host_pages(client: FlaskClient, session: Session, assessment: Assessment) -> dict[str, str]:
    hosts = session.scalars(select(Host).where(Host.scan_id == assessment.scans[0].id)).all()
    return {
        host.hostname: page(client, f"/assessments/{assessment.id}/hosts/{host.id}")
        for host in hosts
    }


def check_section(html: str, key: str) -> str:
    section = re.search(rf'<section [^>]*aria-labelledby="check-{key}".*?</section>', html, re.S)
    assert section is not None, key
    return section.group(0)


# ------------------------------------------------------------------------------ scan history


def test_the_history_gives_the_time_of_every_scan_as_a_moment(
    client: FlaskClient, two: Two
) -> None:
    html = page(client, f"/assessments/{two.assessment.id}/scans")

    assert len(re.findall(MOMENT, html)) == 2  # one row per scan
    assert not re.findall(PLAIN_MOMENT, html)
    assert html.count('<td class="sm:whitespace-nowrap">') == 2  # and the row keeps it on a line


def test_the_history_table_scrolls_on_a_phone_instead_of_squeezing_its_columns(
    client: FlaskClient, two: Two
) -> None:
    """Seven columns do not fit a phone: the cells keep what they say and the table scrolls."""
    html = page(client, f"/assessments/{two.assessment.id}/scans")

    assert '<table class="data-table max-sm:whitespace-nowrap">' in html
    assert html.count('<td class="whitespace-nowrap">') == 2  # how long a scan took stays whole


# ------------------------------------------------------------------------------ comparison


def test_the_comparison_names_its_two_scans_with_moments(client: FlaskClient, two: Two) -> None:
    html = page(
        client,
        f"/assessments/{two.assessment.id}/compare?from={two.older.id}&to={two.newer.id}",
    )

    sentence = re.search(r"From the scan of(.*?)Hosts are matched", html, re.S)
    assert sentence is not None
    assert len(re.findall(MOMENT, sentence.group(1))) == 2
    assert "UTC" not in re.sub(MOMENT, "", sentence.group(1))  # nothing of it left outside


def test_the_summary_of_the_changes_has_two_columns_on_a_phone(
    client: FlaskClient, two: Two
) -> None:
    """Eight figures one below the other were half a screen before any finding."""
    html = page(
        client,
        f"/assessments/{two.assessment.id}/compare?from={two.older.id}&to={two.newer.id}",
    )

    assert '<dl class="grid grid-cols-2 gap-4 lg:grid-cols-4">' in html


# ------------------------------------------------------------------------------ findings, host


def test_findings_host_and_domain_name_their_scan_with_a_moment(
    client: FlaskClient, db_session: Session, vendor: Assessment
) -> None:
    base = f"/assessments/{vendor.id}"
    pages = {
        "findings": page(client, f"{base}/findings"),
        "domain": page(client, f"{base}/domain"),
        **{f"host {name}": html for name, html in host_pages(client, db_session, vendor).items()},
    }

    for name, html in pages.items():
        assert len(re.findall(MOMENT, html)) == 1, name  # the scan, in the line under the title
        assert not re.findall(PLAIN_MOMENT, html), name


# ------------------------------------------------------------------------------ the checks


def test_a_check_keeps_its_time_whole_and_lets_a_long_result_wrap_on_a_phone(
    client: FlaskClient, db_session: Session, vendor: Assessment
) -> None:
    """The registration of a domain read "Expires in 12 days · RESERVED-Internet Assigned Numbers
    Authority" in one badge that could not wrap: the whole page scrolled sideways on a phone."""
    pages = [
        page(client, f"/assessments/{vendor.id}/domain"),
        *host_pages(client, db_session, vendor).values(),
    ]

    for html in pages:
        heads = len(re.findall(r'<h2 id="check-', html))
        assert heads and len(re.findall(CHECK_HEAD, html)) == heads
        times = re.findall(r"<time [^>]*>[^<]*:\d{2} UTC</time>", html)
        assert times
        assert all('class="whitespace-nowrap"' in time for time in times)


def test_tables_of_short_values_scroll_sideways_on_a_phone_instead_of_breaking_their_cells(
    client: FlaskClient, db_session: Session, vendor: Assessment
) -> None:
    """An address, a country, a cookie name: nothing there should be cut into pieces."""
    hosts = host_pages(client, db_session, vendor)

    where = check_section(hosts["plain.example.com"], "ip")
    assert '<table class="data-table max-sm:whitespace-nowrap">' in where
    cookies = check_section(hosts["bad-tls.example.com"], "http")
    assert "Cookies" in cookies
    assert cookies.count('<table class="data-table max-sm:whitespace-nowrap">') == 1
