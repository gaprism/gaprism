"""The assessment page: starting scans, the polled panel, hosts, manual hosts."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import Assessment, Host, Scan
from app.models.base import utc_now
from app.service import scans as scan_service
from app.service import worker
from tests.helpers import create_assessment, create_user, login_as, make_app
from tests.test_engine import CONFIG, FakeCheck, discovery_data


def run_scan_to_completion(
    session: Session,
    *hostnames: str,
    failed: bool = False,
    extra_sources: tuple[dict[str, Any], ...] = (),
) -> None:
    """Drain the queue with a fake discovery (and one fake host check).

    ``extra_sources`` are reported next to the healthy ctlogs source of the fake discovery.
    """
    data = discovery_data(*hostnames)
    data["sources"].extend(extra_sources)
    outcome = (
        CheckOutcome("error", "all_sources_failed", data={"hosts": [], "sources": []})
        if failed
        else CheckOutcome("ok", data=data)
    )
    registry = {
        "discovery": FakeCheck("discovery", "domain", outcome),
        "fake": FakeCheck("fake", "host"),
    }
    http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))
    while worker.process_one(session, "w1", config=CONFIG, http=http, registry=registry):
        pass


@pytest.fixture
def signed_in(client: FlaskClient, db_session: Session) -> tuple[FlaskClient, Assessment, Any]:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "example.com")
    login_as(client, user)
    return client, assessment, user


def test_a_fresh_assessment_offers_to_start_a_scan(signed_in: Any) -> None:
    client, assessment, _ = signed_in
    page = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "No scan has run yet" in page
    assert "Start scan" in page and "Re-scan" not in page
    assert "hx-trigger" not in page  # nothing to poll


def test_starting_a_scan_queues_it_and_the_panel_polls_until_it_finishes(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, _ = signed_in

    response = client.post(f"/assessments/{assessment.id}/scans")
    assert response.status_code == 302
    page = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "Scan queued." in page and "Queued" in page and "Re-scan" in page
    assert 'hx-trigger="every 2s"' in page
    assert f"/assessments/{assessment.id}/scan-panel" in page

    scan = db_session.scalars(select(Scan)).one()
    assert scan.status == "queued"

    run_scan_to_completion(db_session, "api.example.com")
    panel = client.get(f"/assessments/{assessment.id}/scan-panel").get_data(as_text=True)
    assert "Completed" in panel
    assert "hx-trigger" not in panel  # polling stops once the scan is terminal
    assert "api.example.com" in panel and "The domain itself" in panel
    assert "Certificate Transparency" in panel
    assert "ctlogs.dev" in panel  # the source table shows what each source reported
    assert "Discovery may be incomplete" not in panel  # every source delivered


def test_a_second_scan_is_refused_while_one_is_active(signed_in: Any, db_session: Session) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/scans")
    again = client.post(f"/assessments/{assessment.id}/scans", follow_redirects=True)
    assert "already queued or running" in again.get_data(as_text=True)
    assert len(db_session.scalars(select(Scan)).all()) == 1


def test_a_lost_race_to_start_a_scan_is_reported_not_crashed(db_session: Session) -> None:
    """Two simultaneous requests: the database index lets exactly one scan through."""
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "example.com")
    winner = scan_service.start_scan(db_session, assessment, user, CONFIG)
    db_session.commit()

    real = scan_service.get_active_scan
    answers = iter([None])  # the pre-check still sees "no active scan": the race
    with patch.object(
        scan_service,
        "get_active_scan",
        side_effect=lambda *args: next(answers, None) or real(*args),
    ):
        with pytest.raises(scan_service.ScanInProgressError) as raised:
            scan_service.start_scan(db_session, assessment, user, CONFIG)
    assert raised.value.scan.id == winner.id
    assert len(db_session.scalars(select(Scan)).all()) == 1


def test_the_database_allows_only_one_active_scan_per_assessment(db_session: Session) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "example.com")
    db_session.add(Scan(assessment_id=assessment.id, requested_by=user.id, status="running"))
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(Scan(assessment_id=assessment.id, requested_by=user.id, status="queued"))
        db_session.flush()
    db_session.add(Scan(assessment_id=assessment.id, requested_by=user.id, status="completed"))
    db_session.flush()  # finished scans are not limited


def test_the_panel_hints_at_a_missing_worker_after_a_while(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/scans")
    assert "Waiting for a worker" not in client.get(f"/assessments/{assessment.id}").get_data(
        as_text=True
    )

    scan = db_session.scalars(select(Scan)).one()
    scan.created_at = utc_now() - timedelta(seconds=30)
    db_session.commit()
    page = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Waiting for a worker" in page and "flask worker" in page


def test_a_failed_discovery_is_shown_as_a_gap_not_as_an_empty_result(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/scans")
    run_scan_to_completion(db_session, failed=True)

    page = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Completed with gaps" in page
    assert "No certificate source answered" in page
    assert "www.example.com" in page and "Fallback (no source answered)" in page


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({"source": "crtsh", "status": "error", "reason_code": "http_502"}, "HTTP error 502"),
        ({"source": "crtsh", "status": "error", "reason_code": "budget_exceeded"}, "Took too long"),
        (
            {"source": "certspotter", "status": "unavailable", "reason_code": "rate_limited"},
            "Rate limited",
        ),
        ({"source": "certspotter", "status": "ok", "truncated": True}, "Answered · partial"),
    ],
)
def test_a_missing_or_cut_short_source_is_called_out_next_to_a_good_result(
    signed_in: Any, db_session: Session, extra: dict[str, Any], expected: str
) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/scans")
    run_scan_to_completion(db_session, "api.example.com", extra_sources=(extra,))

    page = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "api.example.com" in page and "Completed" in page
    assert "Discovery may be incomplete" in page
    assert "No certificate source answered" not in page  # one source did answer
    names = {"crtsh": "crt.sh", "certspotter": "CertSpotter"}
    assert f"({names[extra['source']]})" in page  # the notice names the source
    assert expected in page  # and the table says why


def test_hosts_are_filtered_and_paged(signed_in: Any, db_session: Session) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/scans")
    run_scan_to_completion(db_session, *(f"h{n:02}.example.com" for n in range(60)))

    first = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Page 1 of 2" in first and "h00.example.com" in first and "h59.example.com" not in first
    assert f"/assessments/{assessment.id}?page=2" in first

    second = client.get(f"/assessments/{assessment.id}?page=2").get_data(as_text=True)
    assert "Page 2 of 2" in second and "h59.example.com" in second

    filtered = client.get(f"/assessments/{assessment.id}?q=h5").get_data(as_text=True)
    assert "h55.example.com" in filtered and "h00.example.com" not in filtered
    assert "No host matches" in client.get(f"/assessments/{assessment.id}?q=zzz").get_data(
        as_text=True
    )


def test_manual_hosts_can_be_added_and_removed(signed_in: Any, db_session: Session) -> None:
    client, assessment, _ = signed_in

    response = client.post(
        f"/assessments/{assessment.id}/hosts",
        data={
            "hostnames": (
                "vpn.example.com, API.example.com\nevil.com *.example.com bad_name example.com"
            )
        },
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    assert "2 host(s) added" in page
    assert "Not added: evil.com (outside example.com)" in page
    assert "Not added: *.example.com (wildcards are patterns, not hosts)" in page
    assert "Not added: bad_name (not a valid hostname)" in page
    assert "Already included: example.com" in page
    db_session.refresh(assessment)
    assert assessment.manual_hosts == ["vpn.example.com", "api.example.com"]

    removed = client.post(
        f"/assessments/{assessment.id}/hosts/remove",
        data={"hostname": "vpn.example.com"},
        follow_redirects=True,
    )
    assert "Removed vpn.example.com." in removed.get_data(as_text=True)
    db_session.refresh(assessment)
    assert assessment.manual_hosts == ["api.example.com"]

    empty = client.post(
        f"/assessments/{assessment.id}/hosts", data={"hostnames": "  "}, follow_redirects=True
    )
    assert "Enter at least one hostname." in empty.get_data(as_text=True)


def test_manual_hosts_join_the_next_scan(signed_in: Any, db_session: Session) -> None:
    client, assessment, _ = signed_in
    client.post(f"/assessments/{assessment.id}/hosts", data={"hostnames": "vpn.example.com"})
    client.post(f"/assessments/{assessment.id}/scans")
    run_scan_to_completion(db_session)

    hosts = {h.hostname: h.source for h in db_session.scalars(select(Host))}
    assert hosts == {"example.com": "apex", "vpn.example.com": "manual"}


def test_nothing_of_a_private_assessment_leaks_to_other_users(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    other = create_user(db_session)
    private = create_assessment(db_session, owner, "secret.example", "private")
    login_as(client, other)

    for method, path in [
        (client.get, f"/assessments/{private.id}"),
        (client.get, f"/assessments/{private.id}/scan-panel"),
        (client.post, f"/assessments/{private.id}/scans"),
        (client.post, f"/assessments/{private.id}/hosts"),
        (client.post, f"/assessments/{private.id}/hosts/remove"),
    ]:
        assert method(path).status_code == 404, path


@pytest.mark.parametrize("suffix", ["scans", "hosts", "hosts/remove"])
def test_state_changing_routes_need_a_csrf_token(
    database_url: str, schema_name: str, suffix: str
) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        user = create_user(db.session())
        assessment = create_assessment(db.session(), user, f"csrf{suffix.replace('/', '')}.example")
        client = app.test_client()
        login_as(client, user)
        assert client.post(f"/assessments/{assessment.id}/{suffix}", data={}).status_code == 400
        db.session.delete(assessment)
        db.session.delete(user)
        db.session.commit()
