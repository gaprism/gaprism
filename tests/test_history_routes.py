"""The scan history and the comparison as pages: who may open them, what they say, escaping."""

from __future__ import annotations

import json
import uuid

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Host, User
from app.service import scans as scan_service
from tests.helpers import audit_rows, create_assessment, create_user, login_as
from tests.test_engine import CONFIG, new_scan
from tests.test_history import D, Two, finish, two_scans

PAGES = ("scans", "compare")


@pytest.fixture
def two(client: FlaskClient, db_session: Session) -> Two:
    scans = two_scans(db_session)
    login_as(client, scans.user)
    return scans


def url(two: Two, what: str, **query: object) -> str:
    base = f"/assessments/{two.assessment.id}/{what}"
    if not query:
        return base
    return base + "?" + "&".join(f"{k}={v}" for k, v in query.items())


def page(client: FlaskClient, address: str) -> str:
    response = client.get(address)
    assert response.status_code == 200, address
    return response.get_data(as_text=True)


# ------------------------------------------------------------------------------ who may


@pytest.mark.parametrize("what", PAGES)
def test_the_pages_need_a_login(client: FlaskClient, two: Two, what: str) -> None:
    with client.session_transaction() as state:
        state.clear()
    response = client.get(url(two, what))
    assert response.status_code == 302 and "/login" in response.headers["Location"]


@pytest.mark.parametrize("what", PAGES)
def test_a_stranger_gets_nothing_not_even_a_hint(
    client: FlaskClient, db_session: Session, two: Two, what: str
) -> None:
    login_as(client, create_user(db_session))
    assert client.get(url(two, what)).status_code == 404
    assert client.get(f"/assessments/{uuid.uuid4()}/{what}").status_code == 404


# ------------------------------------------------------------------------------ the history


def test_the_history_lists_every_scan_with_its_report_and_files(
    client: FlaskClient, two: Two
) -> None:
    html = page(client, url(two, "scans"))

    assert "<h1>Scan history</h1>" in html
    assert html.count("<tr>") == 3  # the header and the two scans
    assert two.user.email in html and html.count("Completed") >= 2
    for scan in (two.older, two.newer):
        assert f'<time datetime="{scan.created_at.isoformat()}">' in html
        for what in ("report", "export/scan.json", "export/hosts.csv", "export/findings.csv"):
            assert f'href="/assessments/{two.assessment.id}/{what}?scan={scan.id}"' in html
    assert "latest" in html
    # only the newer scan has one before it
    compare = f"/assessments/{two.assessment.id}/compare?from={two.older.id}&amp;to={two.newer.id}"
    assert html.count("What changed since the scan before") == 1 and compare in html
    assert 'name="from"' in html and 'name="to"' in html  # and any two can be chosen
    assert 'value="' + str(two.older.id) + '" selected' in html.split('id="compare-from"')[1]
    assert 'value="' + str(two.newer.id) + '" selected' in html.split('id="compare-to"')[1]


def test_a_scan_in_progress_can_be_followed_not_exported(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()
    html = page(client, url(two, "scans"))
    assert "Follow the scan" in html and "Queued" in html
    assert html.count("Report</a>") == 2  # the two that ended, not the one that has not


def test_an_assessment_without_scans_offers_to_start_one(
    client: FlaskClient, db_session: Session
) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "fresh.example")
    login_as(client, user)
    html = page(client, f"/assessments/{assessment.id}/scans")
    assert "No scan has run yet" in html and "Start scan" in html and "<table" not in html


# ------------------------------------------------------------------------------ the comparison


def test_the_newest_two_scans_are_compared_by_default(client: FlaskClient, two: Two) -> None:
    html = page(client, url(two, "compare"))

    assert "<h1>What changed</h1>" in html
    for title in (
        "New findings", "Resolved findings", "Changed severity", "Not re-checked", "New hosts",
        "Hosts no longer found",
    ):  # fmt: skip
        assert title in html
    assert f"delta{D}" in html and f"gamma{D}" in html  # the host that came, the host that did not
    assert "Was Medium, now High." in html
    # nobody has looked at these again, so they are not reported as resolved
    assert f"The HTTP check of beta{D} failed in the newer scan" in html
    assert (
        f"The TLS certificate check of gamma{D} was not run again: "
        "the host is not in the newer scan." in html
    )
    assert "not reported as resolved" in html
    assert "1 of the unchanged" not in html  # nothing was decided about it yet
    assert '<form method="post"' not in html and "Decide" not in html  # reading only


def test_the_same_page_comes_whichever_way_round_the_scans_are_named(
    client: FlaskClient, two: Two
) -> None:
    forward = page(client, url(two, "compare", **{"from": two.older.id, "to": two.newer.id}))
    reverse = page(client, url(two, "compare", **{"from": two.newer.id, "to": two.older.id}))
    assert forward == reverse
    assert forward == page(client, url(two, "compare"))


def test_a_scan_that_did_not_finish_everywhere_says_so(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    two.newer.status = "partial"
    db_session.commit()
    html = page(client, url(two, "compare"))
    assert "The newer scan did not finish everywhere" in html and "Completed with gaps" in html
    assert "The older scan did not finish everywhere" not in html


def test_findings_that_were_cut_are_said_to_be_missing_from_the_comparison(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    assert "Not every finding was kept" not in page(client, url(two, "compare"))
    two.newer.summary = {
        **(two.newer.summary or {}),
        "findings": {**(two.newer.summary or {})["findings"], "dropped": 7},
    }
    db_session.commit()
    assert "Not every finding was kept" in page(client, url(two, "compare"))


def test_an_incomplete_discovery_is_said_next_to_the_hosts_that_seem_to_be_gone(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    from tests.test_history import set_discovery

    set_discovery(
        db_session, two.newer,
        sources=[{"source": "crtsh", "status": "error", "reason_code": "http_404"}],
        counts={"dropped_by_cap": 3},
    )  # fmt: skip
    html = page(client, url(two, "compare"))
    assert "Discovery of the newer scan was incomplete" in html
    assert "these certificate sources did not deliver everything: crt.sh" in html
    assert "3 hosts were over the limit" in html
    assert "does not mean the host is gone" in html


def test_a_scan_without_findings_compares_the_hosts_only(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    two.older.summary = {}
    db_session.commit()
    html = page(client, url(two, "compare"))
    assert "Findings are not compared" in html
    assert "New hosts" in html and f"delta{D}" in html
    assert "Resolved findings" not in html and "Not re-checked" not in html.replace(
        "Not re-checked</dt>", ""
    )


def test_there_is_nothing_to_compare_before_two_scans_have_run_to_the_end(
    client: FlaskClient, db_session: Session
) -> None:
    only = new_scan(db_session)
    finish(db_session, only)
    owner = db_session.get(User, only.requested_by)
    assert owner is not None
    login_as(client, owner)
    html = page(client, f"/assessments/{only.assessment_id}/compare")
    assert "A comparison needs two scans that ran to the end" in html


def test_a_scan_that_does_not_belong_here_is_not_found(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    foreign = new_scan(db_session, "foreign.example")
    finish(db_session, foreign)
    running = scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()
    for query in (
        {"from": foreign.id, "to": two.newer.id},  # another assessment's scan
        {"from": two.older.id, "to": uuid.uuid4()},  # no such scan
        {"from": "nonsense", "to": two.newer.id},
        {"from": two.older.id},  # one is not enough
        {"to": two.newer.id},
        {"from": two.older.id, "to": running.id},  # it has not ended
    ):
        assert client.get(url(two, "compare", **query)).status_code == 404, query


def test_comparing_a_scan_with_itself_goes_back_to_the_history(
    client: FlaskClient, two: Two
) -> None:
    response = client.get(url(two, "compare", **{"from": two.older.id, "to": two.older.id}))
    assert response.status_code == 302 and response.headers["Location"].endswith(
        f"/{two.assessment.id}/scans"
    )
    assert "Choose two different scans to compare." in page(client, response.headers["Location"])


def test_what_comes_from_the_network_is_escaped(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    hostile = '<img src=x onerror="alert(1)">'
    delta = db_session.scalars(
        select(Host).where(Host.scan_id == two.newer.id, Host.hostname == f"delta{D}")
    ).one()
    delta.hostname = hostile
    db_session.commit()
    html = page(client, url(two, "compare"))
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html


# ------------------------------------------------------------------------------ older scans' files


def test_the_report_and_the_files_can_be_those_of_an_older_scan(
    client: FlaskClient, two: Two
) -> None:
    older = json.loads(
        client.get(url(two, "export/scan.json", scan=two.older.id)).get_data(as_text=True)
    )
    newest = json.loads(client.get(url(two, "export/scan.json")).get_data(as_text=True))
    assert older["scan"]["id"] == str(two.older.id) and newest["scan"]["id"] == str(two.newer.id)
    assert {h["hostname"] for h in older["hosts"]} ^ {h["hostname"] for h in newest["hosts"]} == {
        f"gamma{D}", f"delta{D}",
    }  # fmt: skip

    report = page(client, url(two, "report", scan=two.older.id))
    assert f'<time datetime="{two.older.created_at.isoformat()}">' in report
    assert f"gamma{D}" in report and f"delta{D}" not in report
    assert client.get(url(two, "export/hosts.csv", scan=two.older.id)).status_code == 200
    assert client.get(url(two, "export/findings.csv", scan=two.older.id)).status_code == 200


def test_the_export_of_a_scan_that_is_not_ours_or_not_over_is_refused(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    foreign = new_scan(db_session, "foreign.example")
    finish(db_session, foreign)
    running = scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()
    for scan in (foreign.id, uuid.uuid4(), "nonsense"):
        for what in ("report", "export/scan.json", "export/hosts.csv", "export/findings.csv"):
            assert client.get(url(two, what, scan=scan)).status_code == 404, (what, scan)
    response = client.get(url(two, "report", scan=running.id))  # it has not ended
    assert response.status_code == 302 and response.headers["Location"].endswith(
        str(two.assessment.id)
    )


def test_an_export_of_an_older_scan_is_logged_with_that_scan(
    client: FlaskClient, db_session: Session, two: Two
) -> None:
    client.get(url(two, "export/scan.json", scan=two.older.id))
    (entry,) = audit_rows(db_session, "export.json")
    assert entry.subject == str(two.older.id) and entry.assessment_id == two.assessment.id


# ------------------------------------------------------------------------------ from the assessment


def test_the_assessment_page_leads_to_the_history_and_to_the_last_change(
    client: FlaskClient, two: Two
) -> None:
    html = page(client, f"/assessments/{two.assessment.id}")
    assert f'href="/assessments/{two.assessment.id}/scans"' in html and "Scan history" in html
    assert f"/compare?from={two.older.id}&amp;to={two.newer.id}" in html
    assert "What changed since the scan before" in html
