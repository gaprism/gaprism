"""The report as a document: the logo in its header, every time of day in one piece, and a
stylesheet that follows the identity statement (Indigo section headings, tabular figures in the
tables) and keeps the stacked pairs of a phone apart."""

from __future__ import annotations

import re

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models import User
from tests.helpers import PROJECT_ROOT, attributes, login_as
from tests.test_summary import evaluated
from tests.ui.test_brand_assets import LOCKUP, aspect

ASSETS = PROJECT_ROOT / "assets"
STATIC = PROJECT_ROOT / "app" / "static"

MOMENT = (
    r'<time datetime="[^"]+"><span class="whitespace-nowrap">\d{4}-\d{2}-\d{2}</span> '
    r'<span class="whitespace-nowrap">\d{2}:\d{2} UTC</span></time>'
)


@pytest.fixture
def report(client: FlaskClient, db_session: Session) -> str:
    """The report of a finished scan with its findings, as the signed-in owner opens it."""
    scan, _rows = evaluated(db_session, "vendor.example")
    user = db_session.get(User, scan.requested_by)
    assert user is not None
    login_as(client, user)
    response = client.get(f"/assessments/{scan.assessment_id}/report")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def stylesheet() -> str:
    return (ASSETS / "report.css").read_text(encoding="utf-8")


def declarations(selector: str) -> str:
    """What the rule that starts a line with exactly this selector declares."""
    match = re.search(rf"(?:^|\n){re.escape(selector)}\s*\{{([^}}]*)\}}", stylesheet())
    assert match is not None, selector
    return match.group(1)


def between(page: str, start: str, end: str) -> str:
    return page.split(start, 1)[1].split(end, 1)[0]


# ------------------------------------------------------------------------------ the heading


def test_the_report_opens_with_the_logo_of_the_application(report: str) -> None:
    header = re.search(r'<header class="report-heading">\s*(<img [^>]*>)', report)
    assert header is not None  # the first thing in the heading, before the title of the report
    logo = attributes(header.group(1))
    assert logo["class"] == "report-logo" and logo["alt"] == "Gaprism"
    assert logo["src"] == f"/static/brand/{LOCKUP}"
    assert int(logo["width"]) >= 160  # the smallest size the kit allows for the lockup
    assert abs(int(logo["width"]) * aspect(LOCKUP) - int(logo["height"])) <= 1  # not stretched
    assert "display: block" in declarations(".report-logo")  # with room around it


def test_the_title_line_does_not_leave_one_word_alone(report: str) -> None:
    """On a phone the line "Technical due diligence · external view" left "view" alone."""
    assert "text-wrap: pretty" in declarations(".report-heading .eyebrow")


# ------------------------------------------------------------------------------ times


def test_the_meta_names_the_scan_and_the_report_with_moments(report: str) -> None:
    meta = between(report, '<dl class="report-meta">', "</dl>")
    assert len(re.findall(MOMENT, meta)) == 2  # the scan, and when the report was generated


def test_the_evidence_of_a_finding_gives_its_time_as_a_moment(report: str) -> None:
    lines = re.findall(r'<p class="report-source">\s*Evidence:(.*?)</p>', report, re.S)
    assert lines
    for line in lines:
        assert re.search(MOMENT, line), line


def test_the_method_and_the_footer_give_their_times_as_moments(report: str) -> None:
    rules = between(report, "The rules ran on", "</p>")
    assert len(re.findall(MOMENT, rules)) == 1
    footer = between(report, '<footer class="report-footer">', "</footer>")
    assert len(re.findall(MOMENT, footer)) == 2  # the scan, and when the report was generated


def test_no_time_of_day_is_left_as_plain_text(report: str) -> None:
    left = re.sub(r"<time .*?</time>", "", report, flags=re.S)
    assert not re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", left)


def test_a_time_in_the_report_never_breaks() -> None:
    assert "white-space: nowrap" in declarations(".report-paper time")


# ------------------------------------------------------------------------------ the stylesheet


def test_the_section_headings_are_the_brands_indigo() -> None:
    """The identity statement for reports: Paper, Graphite text, restrained Indigo headings."""
    assert "color: var(--color-action)" in declarations(".report-paper section h2")


def test_the_tables_of_the_report_set_their_numbers_in_tabular_figures() -> None:
    assert "font-variant-numeric: tabular-nums" in declarations(".report-table")


def test_the_pairs_of_a_stacked_list_are_set_apart_on_a_phone() -> None:
    """A label and its value, one below the other, ran into the next pair without a gap."""
    phone = re.search(r"@media \(max-width: 640px\) \{(.*?)\n\}", stylesheet(), re.S)
    assert phone is not None
    assert re.search(r"\.report-facts dt\s*\{[^}]*margin-top:\s*10px", phone.group(1))
    assert re.search(
        r"\.report-facts > div:first-child dt\s*\{[^}]*margin-top:\s*0", phone.group(1)
    )


def test_the_committed_copy_of_the_stylesheet_is_the_one_in_assets() -> None:
    """npm run build copies assets/report.css to app/static/css; both are committed."""
    assert (STATIC / "css" / "report.css").read_bytes() == (ASSETS / "report.css").read_bytes()
