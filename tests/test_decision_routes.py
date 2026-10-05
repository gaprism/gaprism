"""Deciding about findings on the pages: the forms, the routes, who may, where they lead back to."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingDisposition, Host, Scan, User
from app.models.base import utc_now
from tests.helpers import create_user, login_as, make_app
from tests.test_decisions import SPF, TLS, row_for
from tests.test_summary import evaluated

Finished = tuple[FlaskClient, Scan, dict[str, Finding]]

SOON = (utc_now().date() + timedelta(days=30)).isoformat()


@pytest.fixture
def finished(client: FlaskClient, db_session: Session) -> Finished:
    scan, rows = evaluated(db_session)
    login_as(client, db_session.get(User, scan.requested_by))
    return client, scan, rows


def decision_url(scan: Scan, finding: Finding) -> str:
    return f"/assessments/{scan.assessment_id}/findings/{finding.id}/decision"


def findings_url(scan: Scan, query: str = "") -> str:
    return f"/assessments/{scan.assessment_id}/findings" + (f"?{query}" if query else "")


def get(client: FlaskClient, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, url
    return response.get_data(as_text=True)


def titles(page: str) -> list[str]:
    """The findings listed on a page, in order (the hidden fields echo the query, so whole pages
    differ even when the list does not)."""
    return re.findall(r"<h3>([^<]+)</h3>", page)


def accept(client: FlaskClient, scan: Scan, finding: Finding, **fields: str) -> Any:
    data = {"action": "decide", "status": "accepted", "reason": "Known and accepted.", **fields}
    return client.post(decision_url(scan, finding), data=data)


# ----- deciding


def test_accepting_a_finding_records_it_and_comes_back_to_the_list(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    response = accept(client, scan, rows[SPF], review_by=SOON, back="findings", q="severity=medium")

    assert response.status_code == 302
    assert response.headers["Location"] == (
        f"/assessments/{scan.assessment_id}/findings?severity=medium#finding-{rows[SPF].id}"
    )
    row = row_for(db_session, scan, rows[SPF])
    assert row is not None and (row.status, row.reason) == ("accepted", "Known and accepted.")
    assert row.review_by is not None and row.review_by.isoformat() == SOON

    page = get(client, response.headers["Location"])
    assert "Finding accepted." in page
    assert "<h3>No SPF record</h3>" not in page  # the open list no longer has it


def test_the_accepted_finding_stays_visible_with_who_when_why_and_until_when(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    accept(
        client, scan, rows[SPF], reason="The vendor sends no mail.\nSecond line.", review_by=SOON
    )
    page = get(client, findings_url(scan, "status=accepted"))

    assert "<h3>No SPF record</h3>" in page
    assert f"Accepted · review by {SOON}" in page  # the chip
    assert "The vendor sends no mail." in page and "Second line." in page
    email = db_session.get(User, scan.requested_by).email  # type: ignore[union-attr]
    assert f"by {email} on {utc_now().date().isoformat()}" in page
    assert f"review by {SOON}" in page
    assert "Change the decision" in page and "Reopen the finding" in page


def test_a_false_positive_and_a_reopening(finished: Finished, db_session: Session) -> None:
    client, scan, rows = finished
    marked = client.post(
        decision_url(scan, rows[TLS]),
        data={"action": "decide", "status": "false_positive", "reason": "A test fixture."},
    )
    assert marked.status_code == 302
    assert "Finding marked as a false positive." in get(client, marked.headers["Location"])
    row = row_for(db_session, scan, rows[TLS])
    assert row is not None and row.status == "false_positive"
    assert "<h3>Certificate not valid</h3>" in get(
        client, findings_url(scan, "status=false_positive")
    )

    reopened = client.post(decision_url(scan, rows[TLS]), data={"action": "reopen"})
    assert "Finding reopened." in get(client, reopened.headers["Location"])
    db_session.expire_all()
    assert row_for(db_session, scan, rows[TLS]) is None
    assert "<h3>Certificate not valid</h3>" in get(client, findings_url(scan))  # open again

    again = client.post(decision_url(scan, rows[TLS]), data={"action": "reopen"})
    assert "This finding was already open." in get(client, again.headers["Location"])


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"reason": ""}, "Give a reason"),
        ({"reason": "   "}, "Give a reason"),
        ({"reason": "x" * 5000}, "too long"),
        ({"status": "banana"}, "Choose a decision"),
        ({"status": ""}, "Choose a decision"),
        ({"review_by": "next week"}, "not a valid date"),
        ({"review_by": "2001-01-01"}, "after today"),
    ],
)
def test_a_decision_that_cannot_be_recorded_says_why_and_changes_nothing(
    finished: Finished, db_session: Session, fields: dict[str, str], message: str
) -> None:
    client, scan, rows = finished
    response = accept(client, scan, rows[SPF], **fields)
    assert response.status_code == 302
    assert message in get(client, response.headers["Location"])
    assert row_for(db_session, scan, rows[SPF]) is None


def test_a_lapsed_acceptance_is_open_again_and_says_so(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    db_session.add(
        FindingDisposition(
            assessment_id=scan.assessment_id, fingerprint=rows[SPF].fingerprint,
            status="accepted", reason="For the audit.", decided_by=scan.requested_by,
            review_by=utc_now().date() - timedelta(days=3),
        )
    )  # fmt: skip
    db_session.commit()

    page = get(client, findings_url(scan))  # the open list
    assert "<h3>No SPF record</h3>" in page
    assert "Acceptance expired" in page
    assert "Accepted, but the review date has passed: the finding is open again." in page
    assert "For the audit." in page  # what was decided stays readable


# ----- the forms


def test_the_findings_page_offers_the_decision_forms(finished: Finished) -> None:
    client, scan, rows = finished
    page = get(client, findings_url(scan))
    action = f'action="/assessments/{scan.assessment_id}/findings/{rows[SPF].id}/decision"'
    assert action in page and 'name="csrf_token"' in page
    assert (
        'name="status" value="accepted" checked' in page
        and 'name="status" value="false_positive"' in page
    )
    assert 'name="reason" rows="3" maxlength="2000" required' in page
    assert 'name="review_by" type="date" min="' in page and 'max="' in page
    assert "Reopen the finding" not in page  # nothing to take back yet
    assert 'name="back" value="findings"' in page


def test_the_forms_return_to_the_page_and_filters_they_were_used_on(finished: Finished) -> None:
    client, scan, _ = finished
    page = get(client, findings_url(scan, "severity=medium&page=1"))
    assert 'name="q" value="severity=medium&amp;page=1"' in page


def test_the_page_of_a_host_has_the_forms_too_and_leads_back_to_itself(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    host = db_session.scalars(
        select(Host).where(Host.scan_id == scan.id, Host.hostname == "bad-tls.example.com")
    ).one()
    page = get(client, f"/assessments/{scan.assessment_id}/hosts/{host.id}")
    assert 'name="back" value="host"' in page and f'name="host" value="{host.id}"' in page

    response = client.post(
        decision_url(scan, rows[TLS]),
        data={
            "action": "decide",
            "status": "accepted",
            "reason": "Known.",
            "back": "host",
            "host": str(host.id),
        },
    )
    assert response.headers["Location"] == (
        f"/assessments/{scan.assessment_id}/hosts/{host.id}#finding-{rows[TLS].id}"
    )
    after = get(client, response.headers["Location"])
    assert "Finding accepted." in after and "Known." in after
    assert after.index("<h3>Certificate not valid</h3>") > after.index(
        "<h3>Weak certificate key</h3>"
    )  # open first


# ----- where they lead back to


@pytest.mark.parametrize(
    "form",
    [
        {"back": "http://evil.example/", "q": "next=http://evil.example"},
        {
            "back": "findings",
            "q": "status=all&next=http://evil.example&rule=<script>&page=-1&host=zzz&severity=catastrophic",
        },
        {"back": "host", "host": "not-a-uuid", "q": "//evil.example"},
        {"back": "findings", "q": "status=" + "a" * 5000},
    ],
)
def test_a_decision_never_redirects_anywhere_but_to_the_findings(
    finished: Finished, form: dict[str, str]
) -> None:
    client, scan, rows = finished
    response = accept(client, scan, rows[SPF], **form)
    location = response.headers["Location"]
    assert location.startswith(f"/assessments/{scan.assessment_id}/findings")
    assert "evil" not in location and "<" not in location and "zzz" not in location
    assert location.endswith(f"#finding-{rows[SPF].id}")


def test_the_filters_that_come_back_are_the_valid_ones(finished: Finished) -> None:
    client, scan, rows = finished
    host = uuid.uuid4()
    q = f"status=accepted&severity=high&rule=TLS_INVALID&host={host}&page=3&junk=1"
    response = accept(client, scan, rows[SPF], back="findings", q=q)
    path, anchor = response.headers["Location"].split("#")
    assert path.startswith(findings_url(scan) + "?")
    assert set(path.split("?", 1)[1].split("&")) == {
        "status=accepted", "severity=high", "rule=TLS_INVALID", f"host={host}", "page=3",
    }  # fmt: skip
    assert anchor == f"finding-{rows[SPF].id}"


# ----- who may decide


def test_a_stranger_cannot_decide_and_nothing_changes(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    login_as(client, create_user(db_session))
    assert accept(client, scan, rows[SPF]).status_code == 404
    assert client.post(decision_url(scan, rows[SPF]), data={"action": "reopen"}).status_code == 404
    assert client.get(findings_url(scan)).status_code == 404
    assert row_for(db_session, scan, rows[SPF]) is None


def test_a_finding_of_another_assessment_is_not_found_even_for_its_neighbour(
    finished: Finished, db_session: Session
) -> None:
    client, scan, _ = finished
    _, others = evaluated(db_session)  # a finished scan of somebody else's assessment
    foreign = next(iter(others.values()))
    assert accept(client, scan, foreign).status_code == 404  # unknown here, whatever it says there
    assert db_session.scalars(select(FindingDisposition)).all() == []


def test_deciding_needs_a_login(finished: Finished) -> None:
    client, scan, rows = finished
    with client.session_transaction() as state:
        state.clear()
    response = accept(client, scan, rows[SPF])
    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_deciding_needs_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        user = create_user(db.session())
        client = app.test_client()
        login_as(client, user)
        url = f"/assessments/{uuid.uuid4()}/findings/{uuid.uuid4()}/decision"
        assert (
            client.post(
                url, data={"action": "decide", "status": "accepted", "reason": "x"}
            ).status_code
            == 400
        )
        db.session.delete(user)
        db.session.commit()


# ----- what people type is escaped


def test_a_hostile_reason_is_shown_as_text(finished: Finished, db_session: Session) -> None:
    client, scan, rows = finished
    evil = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    accept(client, scan, rows[TLS], reason=evil)
    host = db_session.scalars(
        select(Host).where(Host.scan_id == scan.id, Host.hostname == "bad-tls.example.com")
    ).one()
    pages = [
        get(client, findings_url(scan, "status=accepted")),
        get(client, f"/assessments/{scan.assessment_id}/hosts/{host.id}"),
    ]
    for page in pages:
        assert "<script>alert(1)" not in page and "<img src=x" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    # and in the edit form, where the text goes back into the textarea
    assert (
        "&lt;script&gt;alert(1)&lt;/script&gt;"
        in pages[0].split('id="reason-' + str(rows[TLS].id))[1]
    )


# ----- the other pages follow


def test_the_other_pages_count_open_findings_and_say_what_was_decided(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    before = get(client, f"/assessments/{scan.assessment_id}")
    assert "Not counted as open" not in before
    accept(client, scan, rows[SPF])
    client.post(
        decision_url(scan, rows[TLS]),
        data={"action": "decide", "status": "false_positive", "reason": "Fixture."},
    )

    page = get(client, f"/assessments/{scan.assessment_id}")
    panel = page.split('id="findings-title"')[1].split("</section>")[0]
    assert " open)" in panel and "Not counted as open:" in panel
    assert "1 accepted" in panel and "1 false positive" in panel
    base = f"/assessments/{scan.assessment_id}/findings"
    assert (
        f'href="{base}?status=accepted"' in panel
        and f'href="{base}?status=false_positive"' in panel
    )
    assert "No SPF record" not in panel  # an open-rules table
    secure = page.split('id="secure-title"')[1].split("</article>")[0]
    assert f'href="{base}?status=accepted"' in secure and "1 accepted" in secure


def test_the_status_tabs_the_host_filter_and_nonsense_in_the_query(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    accept(client, scan, rows[SPF])
    page = get(client, findings_url(scan))
    tabs = page.split('aria-label="Status"')[1].split("</nav>")[0]
    assert re.search(r'aria-current="page">Open<span', tabs)  # the open tab is the current one
    for label in ("Open", "Accepted", "False positive", "All"):
        assert f"{label}<span" in tabs
    assert 'Accepted<span class="ml-1 text-muted">(1)</span>' in tabs

    assert titles(get(client, findings_url(scan, "status=bogus"))) == titles(
        get(client, findings_url(scan))
    )  # = open
    host = db_session.scalars(
        select(Host).where(Host.scan_id == scan.id, Host.hostname == "plain.example.com")
    ).one()
    one_host = get(client, findings_url(scan, f"host={host.id}"))
    assert (
        "<h3>HTTP is not redirected to HTTPS</h3>" not in one_host
        and "plain.example.com" in one_host
    )
    assert f'<option value="{host.id}" selected>plain.example.com</option>' in one_host
    assert "<h3>No SPF record</h3>" not in one_host  # a domain finding is nobody's host
    assert "<h3>Certificate not valid</h3>" not in one_host  # and another host's is not its own
    assert titles(get(client, findings_url(scan, "host=not-a-uuid"))) == titles(
        get(client, findings_url(scan))
    )


def test_an_empty_list_says_why_it_is_empty(finished: Finished) -> None:
    client, scan, _ = finished
    assert "Nobody has decided about a finding of this kind yet." in get(
        client, findings_url(scan, "status=accepted")
    )
    assert "No finding matches this filter." in get(client, findings_url(scan, "rule=NO_SUCH_RULE"))
