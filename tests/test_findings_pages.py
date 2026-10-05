"""Findings on the pages: the assessment panel and hosts table, a host's page, the findings page."""

from __future__ import annotations

from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import Host, Scan, User
from app.models.base import utc_now
from app.service import findings as findings_service
from tests.helpers import create_assessment, create_user, login_as
from tests.rules.helpers import expired
from tests.test_engine import new_scan
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan

Evaluated = tuple[FlaskClient, Scan, dict[str, Host]]


def evaluate(session: Session, scan: Scan) -> None:
    findings_service.evaluate_scan(session, scan, RULES_CONFIG)
    scan.status, scan.finished_at = "completed", utc_now()
    session.commit()


def sign_in(client: FlaskClient, session: Session, scan: Scan) -> None:
    login_as(client, session.get(User, scan.assessment.created_by))


@pytest.fixture
def evaluated(client: FlaskClient, db_session: Session) -> Evaluated:
    scan, hosts = populated_scan(db_session)
    evaluate(db_session, scan)
    sign_in(client, db_session, scan)
    return client, scan, hosts


def get(client: FlaskClient, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, url
    return response.get_data(as_text=True)


# ------------------------------------------------------------------------------ the assessment


def test_the_assessment_page_shows_one_row_per_rule_that_fired(evaluated: Evaluated) -> None:
    client, scan, _ = evaluated
    html = get(client, f"/assessments/{scan.assessment_id}")

    assert 'id="findings-title"' in html
    assert "The rules that fired" in html
    base = f"/assessments/{scan.assessment_id}/findings"
    assert f'<a class="link" href="{base}?rule=TLS_INVALID">Certificate not valid</a>' in html
    assert f'href="{base}"' in html  # all of them
    assert "The rules only judge what the checks collected." in html  # silence is not a verdict
    assert "Findings by severity" in html
    assert "<h3>" not in html.split('id="findings-title"')[1].split("</section>")[0]  # no detail


def test_the_panel_lists_the_most_serious_rules_and_says_how_many_more_there_are(
    evaluated: Evaluated,
) -> None:
    client, scan, _ = evaluated
    html = get(client, f"/assessments/{scan.assessment_id}")
    panel = html.split('id="findings-title"')[1].split("</section>")[0]
    assert panel.count("<tr>") == 1 + 8  # the header and the first eight rules
    assert "more rules fired, with lower severity." in panel
    rows = panel.split("<tbody>")[1]
    assert rows.rindex(">High<") < rows.index(">Medium<")  # the most serious rules come first


def test_the_hosts_table_shows_the_worst_severity_and_the_count_of_each_host(
    evaluated: Evaluated, db_session: Session
) -> None:
    client, scan, hosts = evaluated
    add_host(db_session, scan, "clean.example.com", {})
    html = get(client, f"/assessments/{scan.assessment_id}")

    assert '<th scope="col">Findings</th>' in html
    assert "High · " in html
    assert f"/hosts/{hosts['bad-tls.example.com'].id}#host-findings-title" in html
    assert '<span class="text-muted">None</span>' in html  # a host the rules had nothing on


def test_the_panel_says_when_failed_checks_leave_gaps(
    evaluated: Evaluated, db_session: Session
) -> None:
    client, scan, _ = evaluated
    add_host(
        db_session, scan, "broken.example.com", {"tls": CheckOutcome("error", "internal_error")}
    )
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert "failed or were unavailable, so what they would have shown is not judged" in html


def test_a_scan_that_is_still_running_has_no_findings_yet(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert "The rules run when the scan has finished." in html
    assert "All findings" not in html and "Findings by severity" not in html
    assert '<span class="text-muted">None</span>' not in html  # "none" would claim a verdict


def test_a_scan_whose_evaluation_failed_says_so(client: FlaskClient, db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    scan.status, scan.finished_at = "completed", utc_now()
    scan.summary = {"findings": {"error": "evaluation_failed"}}
    db_session.commit()
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert "turning its results into findings failed" in html
    assert "All findings" not in html


def test_a_cancelled_scan_has_no_findings_and_says_why(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    scan.status, scan.finished_at = "cancelled", utc_now()
    db_session.commit()
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert (
        "scans that were cancelled, or that ran before the rules existed, are not evaluated" in html
    )


def test_a_scan_the_rules_found_nothing_in_does_not_claim_that_all_is_well(
    client: FlaskClient, db_session: Session
) -> None:
    scan = new_scan(db_session)  # nothing was collected, so nothing can be found
    evaluate(db_session, scan)
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert "No rule fired on what was collected." in html
    assert "The rules only judge what the checks collected." in html
    assert "All findings" not in html  # nothing to list


def test_rules_that_crashed_and_findings_that_were_dropped_are_reported(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    scan.status, scan.finished_at = "completed", utc_now()
    scan.summary = {"findings": {"total": 0, "errors": ["TLS_INVALID"], "dropped": 7}}
    db_session.commit()
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}")
    assert "Some rules could not run" in html and "TLS_INVALID failed" in html
    assert "7 findings beyond the limit per scan were dropped" in html


# ------------------------------------------------------------------------------ a host


def test_the_host_page_lists_its_findings_and_those_of_its_addresses(evaluated: Evaluated) -> None:
    client, scan, hosts = evaluated
    host = hosts["bad-tls.example.com"]
    html = get(client, f"/assessments/{scan.assessment_id}/hosts/{host.id}")

    assert 'id="host-findings-title"' in html
    for title in (
        "Certificate not valid",
        "Weak certificate key",
        "Session cookie without protection flags",
    ):
        assert f"<h3>{title}</h3>" in html
    assert "On the addresses of this host" in html
    assert "<h3>Risky service reachable from the internet</h3>" in html
    assert "A scanner saw MySQL (port 3306) open on 93.184.216.34." in html
    assert "Confirmed for this hostname" in html or "Seen on the address only" in html
    # the evidence is on the same page, a section further down
    assert f'href="/assessments/{scan.assessment_id}/hosts/{host.id}#check-tls"' in html
    assert 'id="check-tls"' in html
    assert f'href="/assessments/{scan.assessment_id}/hosts/{host.id}#check-ports"' in html


def test_a_host_without_findings_does_not_look_clean_by_silence(
    evaluated: Evaluated, db_session: Session
) -> None:
    client, scan, _ = evaluated
    clean = add_host(db_session, scan, "clean.example.com", {})
    html = get(client, f"/assessments/{scan.assessment_id}/hosts/{clean.id}")
    assert "No rule fired for this host." in html
    assert "a check that failed or found nothing proves nothing" in html


def test_a_host_of_a_running_scan_has_no_findings_yet(
    client: FlaskClient, db_session: Session
) -> None:
    scan, hosts = populated_scan(db_session)
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}/hosts/{hosts['bad-tls.example.com'].id}")
    assert "The rules run when the scan has finished." in html


# ------------------------------------------------------------------------------ the findings page


def test_the_findings_page_lists_everything_most_serious_first(evaluated: Evaluated) -> None:
    client, scan, _ = evaluated
    html = get(client, f"/assessments/{scan.assessment_id}/findings")

    assert "<h1>Findings</h1>" in html
    assert html.index("<h3>Certificate not valid</h3>") < html.index(
        "<h3>DNSSEC is not enabled</h3>"
    )
    assert "<h3>No SPF record</h3>" in html and "<h3>Domain registration expires soon</h3>" in html
    assert "Host" in html and "bad-tls.example.com" in html  # who each finding is about
    assert "The domain itself" in html
    assert "What to do" in html and "Show the evidence" in html
    # many links read "Show the evidence": each one names its finding for screen readers
    assert 'aria-label="Show the evidence for: Certificate not valid"' in html
    assert f'href="/assessments/{scan.assessment_id}/domain#check-email"' in html


def test_the_findings_page_filters_by_severity_and_by_rule(evaluated: Evaluated) -> None:
    client, scan, _ = evaluated
    base = f"/assessments/{scan.assessment_id}/findings"

    high = get(client, f"{base}?severity=high")
    assert "<h3>Certificate not valid</h3>" in high
    assert "<h3>DNSSEC is not enabled</h3>" not in high
    assert '<option value="high" selected>' in high

    one_rule = get(client, f"{base}?rule=SPF_MISSING")
    assert "<h3>No SPF record</h3>" in one_rule
    assert "<h3>Certificate not valid</h3>" not in one_rule
    assert '<option value="SPF_MISSING" selected>' in one_rule

    nothing = get(client, f"{base}?rule=NO_SUCH_RULE")
    assert "No finding matches this filter." in nothing

    not_a_filter = get(client, f"{base}?severity=catastrophic")
    assert (
        "<h3>Certificate not valid</h3>" in not_a_filter and "DNSSEC is not enabled" in not_a_filter
    )


def test_the_findings_page_is_paged(evaluated: Evaluated, db_session: Session) -> None:
    client, scan, _ = evaluated
    for number in range(60):
        add_host(db_session, scan, f"h{number:02d}.example.com", {"tls": expired()})
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    base = f"/assessments/{scan.assessment_id}/findings"

    first = get(client, base)
    assert "Page 1 of " in first and ">Next</a>" in first and ">Previous</a>" not in first
    second = get(client, f"{base}?page=2")
    assert "Page 2 of " in second and ">Previous</a>" in second
    assert "?page=" not in second.split(">Previous</a>")[0].rsplit("href=", 1)[-1]  # back to 1
    nonsense = get(client, f"{base}?page=zzz")  # nonsense is page one
    assert "Page 1 of " in nonsense and ">Previous</a>" not in nonsense


def test_the_findings_page_without_a_scan(client: FlaskClient, db_session: Session) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "fresh.example")
    login_as(client, user)
    html = get(client, f"/assessments/{assessment.id}/findings")
    assert "No scan has run yet. Start one to see findings." in html


def test_the_findings_page_of_a_scan_that_is_not_evaluated(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    sign_in(client, db_session, scan)
    html = get(client, f"/assessments/{scan.assessment_id}/findings")
    assert "The rules run when the scan has finished." in html


# ------------------------------------------------------------------------------ access


def test_findings_are_private_to_those_who_may_open_the_assessment(
    evaluated: Evaluated, db_session: Session
) -> None:
    client, scan, hosts = evaluated
    stranger = create_user(db_session)
    login_as(client, stranger)
    for url in (
        f"/assessments/{scan.assessment_id}/findings",
        f"/assessments/{scan.assessment_id}/hosts/{hosts['bad-tls.example.com'].id}",
    ):
        assert client.get(url).status_code == 404


def test_findings_need_a_login(evaluated: Evaluated) -> None:
    client, scan, _ = evaluated
    with client.session_transaction() as state:
        state.clear()
    response = client.get(f"/assessments/{scan.assessment_id}/findings")
    assert response.status_code == 302 and "/login" in response.headers["Location"]


# ------------------------------------------------------------------------------ hostile data


HOSTILE = '<img src=x onerror="alert(1)">.evil.example'


def test_whatever_the_network_said_is_escaped(client: FlaskClient, db_session: Session) -> None:
    """A DNS alias target is attacker-controlled text; it reaches the page through a finding."""
    scan, _ = populated_scan(db_session)
    hostile = add_host(
        db_session,
        scan,
        "evil.example.com",
        {
            "dns": CheckOutcome(
                "ok",
                data={
                    "dangling_cname": True,
                    "canonical_name": HOSTILE,
                    "addresses": [],
                    "blocked": [],
                },
            )
        },
    )
    evaluate(db_session, scan)
    sign_in(client, db_session, scan)
    base = f"/assessments/{scan.assessment_id}"

    pages: list[Any] = [
        get(client, f"{base}/findings?rule=DANGLING_CNAME"),
        get(client, f"{base}/hosts/{hostile.id}"),
        get(client, base),
    ]
    for html in pages:
        assert "<img src=x" not in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;.evil.example" in pages[0]
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;.evil.example" in pages[1]
