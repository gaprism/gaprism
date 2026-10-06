"""Archiving and deleting assessments: who may, what changes, what goes and what stays."""

from __future__ import annotations

import uuid
from dataclasses import asdict

import pytest
from flask import g
from flask.testing import FlaskClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Assessment, CheckResult, Finding, FindingDisposition, Host, Scan, User
from app.service import assessments as assessment_service
from app.service import scans as scan_service
from app.service import users as user_service
from tests.helpers import audit_rows, create_assessment, create_user, login_as, make_app
from tests.test_engine import CONFIG
from tests.test_summary import decide as record_decision
from tests.test_summary import evaluated


def administrator(session: Session) -> User:
    user = user_service.create_admin(session, "boss@example.org", "Administrator-Pass-1")
    session.commit()
    return user


def how_many(session: Session, model: type, column: object, value: object) -> int:
    return int(session.scalar(select(func.count()).select_from(model).where(column == value)) or 0)


def page(client: FlaskClient, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, url
    return response.get_data(as_text=True)


# ------------------------------------------------------------------------------ archiving


def test_archiving_hides_an_assessment_from_the_list_and_restoring_brings_it_back(
    db_session: Session,
) -> None:
    owner = create_user(db_session)
    one = create_assessment(db_session, owner, "one.example")
    two = create_assessment(db_session, owner, "two.example")

    assert assessment_service.archive(db_session, one, owner) is True
    db_session.commit()
    assert {a.id for a in assessment_service.list_visible(db_session, owner)} == {two.id}
    assert {a.id for a in assessment_service.list_visible(db_session, owner, archived=True)} == {
        one.id
    }
    assert {a.id for a in assessment_service.list_visible(db_session, owner, archived=None)} == {
        one.id,
        two.id,
    }
    assert one.archived_at is not None

    assert assessment_service.archive(db_session, one, owner) is False  # already archived
    assert assessment_service.unarchive(db_session, one, owner) is True
    assert assessment_service.unarchive(db_session, one, owner) is False  # not archived any more
    assert one.archived_at is None
    assert {a.id for a in assessment_service.list_visible(db_session, owner)} == {one.id, two.id}


def test_an_archived_assessment_cannot_be_scanned_and_its_domain_stays_taken(
    db_session: Session,
) -> None:
    owner = create_user(db_session)
    kept = create_assessment(db_session, owner, "kept.example")
    assessment_service.archive(db_session, kept, owner)
    db_session.commit()

    with pytest.raises(assessment_service.AssessmentArchivedError):
        scan_service.start_scan(db_session, kept, owner, CONFIG)
    assert how_many(db_session, Scan, Scan.assessment_id, kept.id) == 0

    with pytest.raises(assessment_service.DuplicateAssessmentError) as raised:
        assessment_service.create_assessment(db_session, owner, "kept.example")
    assert raised.value.existing.id == kept.id and raised.value.existing.archived_at is not None


def test_archiving_and_deleting_wait_for_a_scan(db_session: Session) -> None:
    owner = create_user(db_session)
    busy = create_assessment(db_session, owner, "busy.example")
    scan_service.start_scan(db_session, busy, owner, CONFIG)
    db_session.commit()

    with pytest.raises(assessment_service.AssessmentBusyError):
        assessment_service.archive(db_session, busy, owner)
    with pytest.raises(assessment_service.AssessmentBusyError):
        assessment_service.delete_assessment(db_session, busy, owner)
    assert busy.archived_at is None and db_session.get(Assessment, busy.id) is not None

    scan_service.cancel_active_scan(db_session, busy.id)
    db_session.commit()
    assert scan_service.get_active_scan(db_session, busy.id) is None
    assert assessment_service.archive(db_session, busy, owner) is True


# ------------------------------------------------------------------------------ deleting


def test_deleting_takes_the_scans_hosts_findings_and_decisions_and_nothing_else(
    db_session: Session,
) -> None:
    gone_scan, gone_findings = evaluated(db_session, "gone.example")
    kept_scan, _kept_findings = evaluated(db_session, "kept.example")
    record_decision(db_session, gone_scan, next(iter(gone_findings.values())), "accepted")
    gone = gone_scan.assessment
    gone_assessment_id, gone_scan_id = gone_scan.assessment_id, gone_scan.id
    owner = db_session.get(User, gone_scan.requested_by)
    assert owner is not None
    kept_before = assessment_service.contents(db_session, kept_scan.assessment)
    before = assessment_service.contents(db_session, gone)
    assert min(before.scans, before.hosts, before.findings, before.decisions) >= 1

    taken = assessment_service.delete_assessment(db_session, gone, owner)
    db_session.commit()
    db_session.expire_all()

    assert taken == before
    assert db_session.get(Assessment, gone_assessment_id) is None
    for model, column in (
        (Scan, Scan.id),
        (Host, Host.scan_id),
        (CheckResult, CheckResult.scan_id),
        (Finding, Finding.scan_id),
    ):
        assert how_many(db_session, model, column, gone_scan_id) == 0, model
    assert (
        how_many(
            db_session,
            FindingDisposition,
            FindingDisposition.assessment_id,
            gone_assessment_id,
        )
        == 0
    )
    # the other assessment has all it had
    assert assessment_service.contents(db_session, kept_scan.assessment) == kept_before


def test_the_audit_log_keeps_the_deletion_and_what_came_before_it(db_session: Session) -> None:
    gone_scan, _ = evaluated(db_session, "gone.example")
    kept_scan, _ = evaluated(db_session, "kept.example")
    owner = db_session.get(User, gone_scan.requested_by)
    assert owner is not None
    gone_assessment_id, kept_assessment_id = gone_scan.assessment_id, kept_scan.assessment_id
    counts = assessment_service.contents(db_session, gone_scan.assessment)

    assessment_service.delete_assessment(db_session, gone_scan.assessment, owner)
    db_session.commit()
    db_session.expire_all()

    (deleted,) = audit_rows(db_session, "assessment.deleted")
    assert deleted.actor_id == owner.id and deleted.subject == str(gone_assessment_id)
    assert deleted.details["domain"] == "gone.example"
    assert {key: deleted.details[key] for key in asdict(counts)} == asdict(counts)
    assert deleted.details["visibility"] == "private" and deleted.details["archived"] is False
    assert deleted.assessment_id is None  # the link goes with the assessment, the entry stays

    started = {e.details["domain"]: e for e in audit_rows(db_session, "scan.started")}
    assert started["gone.example"].assessment_id is None  # earlier entries lose the link, too
    assert started["kept.example"].assessment_id == kept_assessment_id


def test_every_change_is_in_the_audit_log(db_session: Session) -> None:
    owner = create_user(db_session)
    thing = create_assessment(db_session, owner, "thing.example")
    assessment_service.archive(db_session, thing, owner)
    assessment_service.unarchive(db_session, thing, owner)
    assessment_service.archive(db_session, thing, owner)
    assessment_service.delete_assessment(db_session, thing, owner)
    db_session.commit()

    entries = audit_rows(
        db_session, "assessment.archived", "assessment.unarchived", "assessment.deleted"
    )
    assert [e.action for e in entries] == [
        "assessment.archived",
        "assessment.unarchived",
        "assessment.archived",
        "assessment.deleted",
    ]
    assert all(e.actor_id == owner.id and e.details["domain"] == "thing.example" for e in entries)
    assert entries[-1].details["archived"] is True  # it was archived when it was deleted


# ------------------------------------------------------------------------------ who may


def test_only_the_owner_and_the_administrators_may_archive_or_delete(
    client: FlaskClient, db_session: Session
) -> None:
    owner, colleague, stranger = (
        create_user(db_session),
        create_user(db_session),
        create_user(db_session),
    )
    boss = administrator(db_session)
    shared = create_assessment(db_session, owner, "shared.example", visibility="team")
    private = create_assessment(db_session, owner, "private.example")

    def manage_urls(a: Assessment) -> list[tuple[str, str]]:
        base = f"/assessments/{a.id}"
        return [("post", f"{base}/archive"), ("post", f"{base}/unarchive"),
                ("get", f"{base}/delete"), ("post", f"{base}/delete")]  # fmt: skip

    login_as(client, colleague)
    for method, url in manage_urls(shared):  # can open it, but not hide or delete it
        assert getattr(client, method)(url).status_code == 403, url
    for method, url in manage_urls(private):  # cannot even tell that it exists
        assert getattr(client, method)(url).status_code == 404, url
    login_as(client, stranger)
    for method, url in manage_urls(private):
        assert getattr(client, method)(url).status_code == 404, url

    with client.session_transaction() as state:
        state.clear()
    g.pop("_login_user", None)  # the shared app context would still know the last user
    for method, url in manage_urls(shared):
        response = getattr(client, method)(url)
        assert response.status_code == 302 and "/login" in response.headers["Location"], url

    login_as(client, boss)  # an administrator may, also for somebody else's private assessment
    assert client.get(f"/assessments/{private.id}/delete").status_code == 200
    assert client.post(f"/assessments/{private.id}/archive").status_code == 302
    assert db_session.get(Assessment, private.id).archived_at is not None
    login_as(client, owner)
    assert client.post(f"/assessments/{shared.id}/archive").status_code == 302
    (archived, *_rest) = audit_rows(db_session, "assessment.archived")
    assert archived.actor_id == boss.id  # who did it is in the log


def test_the_owner_sees_the_buttons_and_a_colleague_does_not(
    client: FlaskClient, db_session: Session
) -> None:
    owner, colleague = create_user(db_session), create_user(db_session)
    shared = create_assessment(db_session, owner, "shared.example", visibility="team")
    url = f"/assessments/{shared.id}"
    login_as(client, owner)
    assert "Archive or delete" in page(client, url)
    login_as(client, colleague)
    assert "Archive or delete" not in page(client, url)


# ------------------------------------------------------------------------------ the pages


def test_the_list_has_an_archive_that_is_counted_and_listed(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    create_assessment(db_session, owner, "live-one.example")
    create_assessment(db_session, owner, "live-two.example")
    old = create_assessment(db_session, owner, "old.example")
    login_as(client, owner)

    assert "Archived (0)" in page(client, "/assessments/")
    assert "Nothing is archived" in page(client, "/assessments/?view=archived")

    response = client.post(f"/assessments/{old.id}/archive", follow_redirects=True)
    listing = response.get_data(as_text=True)
    assert "Archived. It is hidden from the list" in listing
    assert "Active (2)" in listing and "Archived (1)" in listing
    assert "old.example" not in listing.split("<tbody>")[1]
    assert "live-one.example" in listing and "live-two.example" in listing

    archive = page(client, "/assessments/?view=archived")
    assert "old.example" in archive and "live-one.example" not in archive
    assert '<th scope="col">Archived</th>' in archive


def test_an_archived_assessment_says_so_and_offers_no_way_to_change_it(
    client: FlaskClient, db_session: Session
) -> None:
    scan, findings = evaluated(db_session, "report.example")
    owner = db_session.get(User, scan.requested_by)
    assert owner is not None
    login_as(client, owner)
    url = f"/assessments/{scan.assessment_id}"
    live = page(client, url)
    assert "Re-scan" in live and "Add hosts" in live and "Archive" in live

    client.post(f"{url}/archive")
    archived = page(client, url)
    assert "This assessment is archived." in archived and "Restore" in archived
    assert "Re-scan" not in archived and "Start scan" not in archived
    assert "Add hosts" not in archived and 'name="hostnames"' not in archived
    finding = next(iter(findings.values()))
    assert f"/findings/{finding.id}/decision" not in page(client, f"{url}/findings")
    assert "Re-scan" not in page(client, f"{url}/scans")
    # what is already there can still be read and exported
    assert client.get(f"{url}/report").status_code == 200
    assert client.get(f"{url}/export/scan.json").status_code == 200

    restored = client.post(f"{url}/unarchive", follow_redirects=True).get_data(as_text=True)
    assert "Restored from the archive." in restored and "Re-scan" in restored
    assert "This assessment is archived." not in restored


def test_an_archived_assessment_refuses_scans_hosts_and_decisions(
    client: FlaskClient, db_session: Session
) -> None:
    scan, findings = evaluated(db_session, "readonly.example")
    owner = db_session.get(User, scan.requested_by)
    assert owner is not None
    login_as(client, owner)
    base = f"/assessments/{scan.assessment_id}"
    client.post(f"{base}/archive")
    scans_before = how_many(db_session, Scan, Scan.assessment_id, scan.assessment_id)
    refusal = "This assessment is archived and read-only. Restore it to change it."

    finding = next(iter(findings.values()))
    attempts = [
        (f"{base}/scans", {}),
        (f"{base}/hosts", {"hostnames": "vpn.readonly.example"}),
        (f"{base}/hosts/remove", {"hostname": "vpn.readonly.example"}),
        (
            f"{base}/findings/{finding.id}/decision",
            {"action": "decide", "status": "accepted", "reason": "no"},
        ),
    ]
    for url, data in attempts:
        response = client.post(url, data=data, follow_redirects=True)
        assert refusal in response.get_data(as_text=True), url

    assert how_many(db_session, Scan, Scan.assessment_id, scan.assessment_id) == scans_before
    assert db_session.get(Assessment, scan.assessment_id).manual_hosts == []
    assert (
        how_many(
            db_session, FindingDisposition, FindingDisposition.assessment_id, scan.assessment_id
        )
        == 0
    )


def test_the_new_assessment_page_says_that_the_domain_is_archived(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    taken = create_assessment(db_session, owner, "taken.example")
    assessment_service.archive(db_session, taken, owner)
    db_session.commit()
    login_as(client, owner)
    response = client.post(
        "/assessments/new", data={"domain": "taken.example", "visibility": "private"}
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200 and "already exists" in body
    assert "archived: restore it from its page" in body
    assert how_many(db_session, Assessment, Assessment.domain, "taken.example") == 1


# ------------------------------------------------------------------------------ the confirmation


def test_deleting_needs_the_domain_to_be_typed(client: FlaskClient, db_session: Session) -> None:
    scan, _ = evaluated(db_session, "gone.example")
    owner = db_session.get(User, scan.requested_by)
    assert owner is not None
    login_as(client, owner)
    url = f"/assessments/{scan.assessment_id}/delete"

    form = page(client, url)
    assert "Delete this assessment?" in form and "gone.example" in form
    counts = assessment_service.contents(db_session, scan.assessment)
    assert f"<dd>{counts.hosts}</dd>" in form and f"<dd>{counts.findings}</dd>" in form
    assert 'name="confirm"' in form and "Delete permanently" in form

    wrong = client.post(url, data={"confirm": "other.example"})
    assert wrong.status_code == 200
    assert "That is not the domain, so nothing was deleted." in wrong.get_data(as_text=True)
    assert db_session.get(Assessment, scan.assessment_id) is not None
    assert client.post(url, data={}).status_code == 200  # an empty box is not the domain either

    done = client.post(url, data={"confirm": "  GONE.example "}, follow_redirects=True)
    assert "Deleted gone.example." in done.get_data(as_text=True)
    assert db_session.get(Assessment, scan.assessment_id) is None
    assert client.get(url).status_code == 404
    assert client.get(f"/assessments/{scan.assessment_id}").status_code == 404


@pytest.mark.parametrize(
    ("canonical", "display", "typed"),
    [
        ("xn--bcher-kva.example", "bücher.example", "bücher.example"),
        ("xn--mnchen-3ya.example", "münchen.example", "xn--mnchen-3ya.example"),
    ],
)
def test_an_international_domain_may_be_typed_either_way(
    client: FlaskClient, db_session: Session, canonical: str, display: str, typed: str
) -> None:
    owner = create_user(db_session)
    international = Assessment(domain=canonical, domain_display=display, created_by=owner.id)
    db_session.add(international)
    db_session.commit()
    login_as(client, owner)
    response = client.post(f"/assessments/{international.id}/delete", data={"confirm": typed})
    assert response.status_code == 302
    assert db_session.get(Assessment, international.id) is None


def test_a_running_scan_stops_the_deletion_and_the_archiving_on_the_pages(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    busy = create_assessment(db_session, owner, "busy.example")
    scan_service.start_scan(db_session, busy, owner, CONFIG)
    db_session.commit()
    login_as(client, owner)
    base = f"/assessments/{busy.id}"

    form = page(client, f"{base}/delete")
    assert "A scan is queued or running" in form and 'name="confirm"' not in form
    posted = client.post(f"{base}/delete", data={"confirm": "busy.example"}, follow_redirects=True)
    assert "before deleting it" in posted.get_data(as_text=True)
    archived = client.post(f"{base}/archive", follow_redirects=True)
    assert "before archiving it" in archived.get_data(as_text=True)
    assert db_session.get(Assessment, busy.id) is not None and busy.archived_at is None


def test_the_audit_page_shows_the_deletion_of_an_assessment_that_is_gone(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    boss = administrator(db_session)
    gone = create_assessment(db_session, owner, "gone.example")
    assessment_service.delete_assessment(db_session, gone, owner)
    db_session.commit()
    login_as(client, boss)
    body = page(client, "/audit/?group=assessment")
    assert "Deleted the assessment" in body and "gone.example" in body and "(removed)" in body


# ------------------------------------------------------------------------------ CSRF


def test_archiving_and_deleting_need_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        user = create_user(db.session())
        client = app.test_client()
        login_as(client, user)
        missing = uuid.uuid4()
        for action in ("archive", "unarchive", "delete"):
            assert client.post(f"/assessments/{missing}/{action}", data={}).status_code == 400
        db.session.delete(user)
        db.session.commit()
