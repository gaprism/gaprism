"""The summary cards on the assessment page: what they say, when they show, how they are escaped."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import CheckResult, Finding, FindingDisposition, Host, Scan, User
from app.models.base import utc_now
from app.service import findings as findings_service
from app.service.geo import IpLocation
from tests.helpers import login_as
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan
from tests.test_summary import dns_outcome, located

Finished = tuple[FlaskClient, Scan, dict[str, Host]]

DISCOVERY = {
    "hosts": [],
    "sources": [],
    "counts": {"names_seen": 7, "out_of_scope": 1},
    "wildcard_patterns": ["*.example.com"],
    "planned": {"dropped_by_cap": 2},
}


def finish(
    session: Session, scan: Scan, status: str = "completed", discovery: dict[str, Any] | None = None
) -> None:
    row = session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id, CheckResult.check_key == "discovery"
        )
    ).one()
    row.status, row.data = "ok", discovery or DISCOVERY
    scan.status, scan.finished_at = status, utc_now()
    session.commit()


def sign_in(client: FlaskClient, session: Session, scan: Scan) -> None:
    login_as(client, session.get(User, scan.assessment.created_by))


def get(client: FlaskClient, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, url
    return response.get_data(as_text=True)


@pytest.fixture
def finished(client: FlaskClient, db_session: Session) -> Finished:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    finish(db_session, scan)
    sign_in(client, db_session, scan)
    return client, scan, hosts


def summary_of(html: str) -> str:
    """The summary section of the page, without the rest of it."""
    return html.split('id="summary-title"')[1].split('id="findings-title"')[0]


# ------------------------------------------------------------------------------ when it shows


def test_the_cards_answer_the_three_questions_with_what_each_does_not_say(
    finished: Finished,
) -> None:
    client, scan, _ = finished
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))

    for question in (
        "Where is the data?",
        "Who processes it?",
        "How secure is the external posture?",
    ):
        assert question in html
    assert "not where data is stored or processed" in html
    assert "legal processors or sub-processors" in html  # a list of providers is not that
    assert "It is not a certification, an audit or a penetration test" in html


def test_there_is_no_summary_while_the_scan_runs(client: FlaskClient, db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert 'id="summary-title"' not in html and "Where is the data?" not in html


def test_a_cancelled_scan_still_says_what_was_looked_at(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    finish(db_session, scan, "cancelled")
    sign_in(client, db_session, scan)
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    assert "Hosts reviewed" in html and "United States" in html
    assert (
        "scans that were cancelled, or that ran before the rules existed, are not evaluated" in html
    )
    assert "open findings" not in html  # nothing was judged, so there is nothing to count


def test_the_polled_panel_carries_the_summary_once_the_scan_is_over(finished: Finished) -> None:
    client, scan, _ = finished
    panel = get(client, f"/assessments/{scan.assessment_id}/scan-panel")
    assert 'id="summary-title"' in panel and "Where is the data?" in panel
    assert "hx-trigger" not in panel  # and polling has stopped


# ------------------------------------------------------------------------------ coverage


def test_the_coverage_adds_up_what_was_seen_reviewed_and_left_out(finished: Finished) -> None:
    client, scan, _ = finished
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    coverage = html.split('id="coverage-title"')[1].split("</section>")[0]

    assert "Names seen" in coverage and "in certificates" in coverage
    assert "Hosts reviewed" in coverage and "fully checked" in coverage
    assert "Answer on HTTPS" in coverage and "1 on plain HTTP only" in coverage
    assert "Not reachable" in coverage and "no public address: 0 · no web server: 0" in coverage
    assert "Not reviewed" in coverage
    assert "outside the domain: 1 · wildcard patterns: 1 · over the limit: 2" in coverage
    assert "1 host could not be classified" in coverage  # cdn.example.com has no web check


def test_names_that_discovery_itself_cut_are_not_reviewed_either(
    client: FlaskClient, db_session: Session
) -> None:
    """A big certificate footprint is capped while the sources are merged, before the scan is
    planned (a live scan of badssl.com saw 9,977 names and reviewed 12): the page must not say
    "over the limit: 0"."""
    scan, _ = populated_scan(db_session)
    scan.options = {**scan.options, "max_hosts": 12}
    finish(
        db_session,
        scan,
        discovery={
            "hosts": [],
            "sources": [],
            "counts": {"names_seen": 9977, "out_of_scope": 0, "dropped_by_cap": 9964},
            "wildcard_patterns": ["*.example.com"],
            "planned": {"hosts": 12, "dropped_by_cap": 0},
        },
    )
    sign_in(client, db_session, scan)
    page = get(client, f"/assessments/{scan.assessment_id}")
    coverage = summary_of(page).split('id="coverage-title"')[1].split("</section>")[0]
    assert "outside the domain: 0 · wildcard patterns: 1 · over the limit: 9964" in coverage
    assert "9964 hosts exceeded the limit of 12 per scan." in page  # and the notice says so


# ------------------------------------------------------------------------------ where


def test_the_where_card_names_countries_cities_and_flags_the_ones_outside(
    finished: Finished,
) -> None:
    client, scan, _ = finished
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    where = html.split('id="where-title"')[1].split("</article>")[0]

    assert "<bdi>United States</bdi>" in where and "<bdi>Switzerland</bdi>" in where
    assert where.count("Outside the allowed area") == 1  # the badge, on the United States only
    assert "<bdi>Ashburn</bdi> (1)" in where and "<bdi>Bern</bdi> (1)" in where
    assert where.index("United States") < where.index("Switzerland")  # outside first
    assert "2 hosts have an address outside the allowed area" in where
    assert "1 of them only through a CDN or anycast edge." in where
    link = f'href="/assessments/{scan.assessment_id}/findings?rule=LOCATION_OUTSIDE_EU_CH"'
    assert link in where  # the matching findings


def test_a_cdn_edge_is_shown_as_edge_and_not_as_a_country(finished: Finished) -> None:
    client, scan, _ = finished
    where = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split('id="where-title"')[
        1
    ]
    where = where.split("</article>")[0]
    assert "1 host sits behind a CDN or anycast network" in where
    assert "<bdi>Cloudflare</bdi> (1)" in where
    assert "the edge, not the data centre" in where
    assert "Canada" not in where and "Toronto" not in where  # the edge is not a place


def test_the_allowed_area_comes_from_the_configuration(
    finished: Finished, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, scan, _ = finished
    monkeypatch.setitem(client.application.config, "DATA_LOCATION_ALLOWED", ["CH", "US", "CA"])
    where = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split('id="where-title"')[
        1
    ]
    where = where.split("</article>")[0]
    assert "Outside the allowed area" not in where and "have an address outside" not in where
    assert "The allowed area has 3 countries." in where


def test_hosts_that_could_not_be_located_are_counted_with_the_reason(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    add_host(
        db_session,
        scan,
        "nowhere.example.com",
        {"dns": dns_outcome("203.0.113.5"), "ip": CheckOutcome("unavailable", "datasets_missing")},
    )
    finish(db_session, scan)
    sign_in(client, db_session, scan)
    where = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split('id="where-title"')[
        1
    ]
    assert (
        "1 host could not be located: Location data not installed." in where.split("</article>")[0]
    )


# ------------------------------------------------------------------------------ who


def test_the_who_card_lists_networks_mail_and_registrar_and_says_what_it_does_not_know(
    finished: Finished,
) -> None:
    client, scan, _ = finished
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    who = html.split('id="who-title"')[1].split("</article>")[0]

    assert "<bdi>Cloudflare</bdi>" in who and "<bdi>Swisscom</bdi>" in who and "AS3303" in who
    assert ">CDN<" in who  # Cloudflare's kind
    assert "<bdi>Google Workspace</bdi>" in who  # the MX hosts
    assert "RESERVED-Internet Assigned Numbers Authority" in who
    # the name servers were never asked in this scan: not "none"
    assert "DNS operators" in who and "Not determined: This check did not run" in who


# ------------------------------------------------------------------------------ secure


def test_the_secure_card_counts_what_is_open_by_severity_and_links_to_each(
    finished: Finished, db_session: Session
) -> None:
    client, scan, _ = finished
    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    secure = html.split('id="secure-title"')[1].split("</article>")[0]
    base = f"/assessments/{scan.assessment_id}/findings"

    assert "open findings" in secure
    assert f'href="{base}?severity=high"' in secure and "High · " in secure
    assert "Most serious" in secure
    assert f'href="{base}?rule=' in secure  # the top rules link to their lists
    assert "4 of 4 hosts fully checked." in secure
    assert "Show hosts with failed checks" not in secure  # no gap, no link


def test_a_gap_in_the_checks_is_said_and_links_to_the_hosts_concerned(
    finished: Finished, db_session: Session
) -> None:
    client, scan, _ = finished
    add_host(db_session, scan, "broken.example.com", {"tls": CheckOutcome("error", "timeout")})
    secure = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split(
        'id="secure-title"'
    )[1]
    secure = secure.split("</article>")[0]
    assert "4 of 5 hosts fully checked." in secure
    assert f'href="/assessments/{scan.assessment_id}?state=problems#host-filter"' in secure


def test_decisions_take_findings_out_of_the_open_count_and_show_as_chips(
    finished: Finished, db_session: Session
) -> None:
    client, scan, _ = finished
    before = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    assert "accepted" not in before.split('id="secure-title"')[1]  # nothing was decided yet

    rows = {
        f.rule_id: f for f in db_session.scalars(select(Finding).where(Finding.scan_id == scan.id))
    }
    for rule_id, status, review in (
        ("SPF_MISSING", "accepted", utc_now().date() + timedelta(days=30)),
        ("DMARC_MISSING", "false_positive", None),
    ):
        db_session.add(
            FindingDisposition(
                assessment_id=scan.assessment_id, fingerprint=rows[rule_id].fingerprint,
                status=status, reason="because", decided_by=scan.requested_by, review_by=review,
            )
        )  # fmt: skip
    db_session.commit()

    secure = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split(
        'id="secure-title"'
    )[1]
    secure = secure.split("</article>")[0]
    assert "1 accepted" in secure and "1 false positive" in secure
    assert "Decided by the team; not counted as open." in secure


def test_a_scan_without_findings_does_not_claim_all_is_well(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    db_session.execute(Finding.__table__.delete().where(Finding.scan_id == scan.id))
    scan.summary = {"findings": {"total": 0, "errors": [], "dropped": 0}}
    finish(db_session, scan)
    sign_in(client, db_session, scan)
    secure = summary_of(get(client, f"/assessments/{scan.assessment_id}")).split(
        'id="secure-title"'
    )[1]
    secure = secure.split("</article>")[0]
    assert "No rule fired on what was collected." in secure
    assert "a check that failed or found nothing proves nothing" in secure


# ------------------------------------------------------------------------------ hostile data


HOSTILE = '<img src=x onerror="alert(1)">'


def test_whatever_the_network_and_the_registries_said_is_escaped(
    client: FlaskClient, db_session: Session
) -> None:
    """City, country, network, MX host and registrar names are third-party text."""
    scan, _ = populated_scan(db_session)
    evil = IpLocation("198.51.100.77", "ZZ", HOSTILE, "EU", "R", HOSTILE, 0.0, 0.0, 64500, HOSTILE)
    add_host(
        db_session,
        scan,
        "evil.example.com",
        {"dns": dns_outcome("198.51.100.77"), "ip": located(evil)},
    )
    for row in db_session.scalars(
        select(CheckResult).where(CheckResult.scan_id == scan.id, CheckResult.host_id.is_(None))
    ):
        if row.check_key == "email":
            row.data = {
                "mx": {
                    "found": True,
                    "records": [{"preference": 1, "host": f"mx.{HOSTILE}.example"}],
                },
                "spf": {"found": True, "senders": [HOSTILE]},
            }
        if row.check_key == "registration":
            row.data = {"registrar": {"name": HOSTILE, "iana_id": None}}
    finish(db_session, scan)
    sign_in(client, db_session, scan)

    html = summary_of(get(client, f"/assessments/{scan.assessment_id}"))
    assert "<img" not in html
    assert (
        html.count("&lt;img src=x onerror=&#34;alert(1)&#34;&gt;") >= 5
    )  # every place it is shown
