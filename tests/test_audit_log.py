"""The audit log: what is written, who may read it, how long it is kept."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_security.utils import hash_password
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.extensions import security
from app.models import AuditEvent, User
from app.service import assessments as assessment_service
from app.service import audit as audit_service
from app.service import scans as scan_service
from app.service import users as user_service
from app.service import worker as worker_service
from tests.helpers import audit_rows, create_assessment, create_user, login_as
from tests.test_engine import CONFIG

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
EXPORT_ADDR = "198.51.100.7"  # documentation addresses: they mark which rows a page shows
LOGIN_ADDR = "192.0.2.44"


def admin(session: Session) -> User:
    user = user_service.create_admin(session, "boss@example.org", "Administrator-Pass-1")
    session.commit()
    return user


def entry(
    session: Session,
    action: str = "scan.started",
    when: datetime = NOW,
    *,
    remote_addr: str | None = None,
    **fields: object,
) -> AuditEvent:
    """Write an entry as if it had happened at `when`."""
    event = audit_service.record(session, action, **fields)  # type: ignore[arg-type]
    event.occurred_at = when
    event.remote_addr = remote_addr
    session.flush()
    return event


def total(html: str) -> int:
    """The number in the "Entries (n)" heading of the audit page."""
    found = re.search(r"Entries <span[^>]*>\((\d+)\)", html)
    assert found, "the page has no entry count"
    return int(found.group(1))


# ------------------------------------------------------------------------------ writing


def test_an_entry_says_who_did_what_to_which_assessment(db_session: Session) -> None:
    owner = create_user(db_session, "owner@example.org")
    assessment = create_assessment(db_session, owner, "vendor.example")
    event = audit_service.record(
        db_session,
        "scan.started",
        actor=owner,
        assessment=assessment,
        subject="the-scan",
        details={"hosts": 3},
    )
    assert (event.actor_id, event.actor_email) == (owner.id, "owner@example.org")
    assert (event.assessment_id, event.subject, event.action) == (
        assessment.id,
        "the-scan",
        "scan.started",
    )
    assert event.details == {"hosts": 3, "domain": "vendor.example"}
    assert event.source == "cli" and event.remote_addr is None  # no request: a command line
    assert event.occurred_at is not None


def test_an_assessment_that_does_not_exist_is_not_linked(db_session: Session) -> None:
    event = audit_service.record(db_session, "hosts.added", assessment=uuid.uuid4())
    assert event.assessment_id is None and "domain" not in event.details


def test_the_facts_of_an_entry_are_kept_small_and_plain(db_session: Session) -> None:
    facts = {
        "fine": 1,
        "Bad Key": 2,  # not a tame name
        "k" * 40: 3,
        "text": "y" * 500,
        "thing": object(),
        "many": list(range(50)),
        "nothing": None,
        "half": 0.5,
        "ratio": float("nan"),  # JSON (and the column) has no NaN
        "huge": float("inf"),
    }
    event = audit_service.record(db_session, "hosts.added", details=facts)
    details = event.details
    assert set(details) == {"fine", "text", "thing", "many", "half", "ratio", "huge"}  # no None
    assert len(details["text"]) == audit_service.MAX_TEXT
    assert details["thing"].startswith("<object object")
    assert len(details["many"]) == audit_service.MAX_DETAILS
    assert (details["half"], details["ratio"], details["huge"]) == (0.5, "nan", "inf")

    many = {f"fact_{n}": n for n in range(40)}
    assert len(audit_service.record(db_session, "hosts.added", details=many).details) == 20


def test_an_entry_is_also_one_safe_line_in_the_log(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.audit"):
        audit_service.record(db_session, "hosts.added", subject="two\nlines", details={"a": "x\ny"})
    messages = [r.getMessage() for r in caplog.records if r.name == "app.audit"]
    assert len(messages) == 1 and "\n" not in messages[0]
    assert messages[0].startswith("hosts.added actor=None assessment=None subject=")
    assert '"two\\nlines"' in messages[0]


# ------------------------------------------------------------------------------ the events


def test_creating_sharing_and_hosts_are_in_the_log(db_session: Session) -> None:
    owner = create_user(db_session, "owner@example.org")
    assessment = assessment_service.create_assessment(db_session, owner, "vendor.example")
    assessment_service.set_visibility(db_session, assessment, "team", owner)
    assessment_service.add_manual_hosts(
        db_session, assessment, "vpn.vendor.example, mail.vendor.example"
    )
    assessment_service.remove_manual_host(db_session, assessment, "vpn.vendor.example")

    entries = audit_rows(db_session)
    assert [e.action for e in entries] == [
        "assessment.created",
        "assessment.shared",
        "hosts.added",
        "hosts.removed",
    ]
    assert entries[0].details == {"visibility": "private", "domain": "vendor.example"}
    assert entries[2].details["count"] == 2 and "vpn.vendor.example" in entries[2].details["hosts"]
    assert entries[3].details["host"] == "vpn.vendor.example"
    assert all(e.assessment_id == assessment.id for e in entries)


def test_starting_and_cancelling_a_scan_are_in_the_log(db_session: Session) -> None:
    owner = create_user(db_session)
    assessment = create_assessment(db_session, owner, "scanned.example")
    scan = scan_service.start_scan(db_session, assessment, owner, CONFIG)
    scan_service.cancel_active_scan(db_session, assessment.id)

    started, cancelled = audit_rows(db_session, "scan.started", "scan.cancelled")
    assert started.subject == cancelled.subject == str(scan.id)
    assert started.actor_id == owner.id and started.details["max_hosts"] == 200
    assert cancelled.assessment_id == assessment.id


def test_signing_in_failing_and_signing_out_are_in_the_log(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    secret = security._totp_factory.generate_totp_secret()
    user = User(
        email="signer@example.org",
        password=hash_password("Correct-Horse-Battery-1"),
        active=True,
        tf_primary_method="authenticator",
        tf_totp_secret=secret,
    )
    db_session.add(user)
    db_session.commit()

    client.post("/auth/login", data={"email": user.email, "password": "wrong"})  # a known account
    client.post("/auth/login", data={"email": "stranger@example.org", "password": "wrong"})
    client.post("/auth/login", data={"email": user.email, "password": "Correct-Horse-Battery-1"})
    code = security._totp_factory.generate_totp_password(secret)
    client.post("/auth/tf-validate", data={"code": code})
    client.post("/auth/logout")

    entries = audit_rows(db_session)
    assert [e.action for e in entries] == ["auth.login_failed", "auth.login", "auth.logout"]
    assert all(e.actor_id == user.id and e.remote_addr == "127.0.0.1" for e in entries)
    assert entries[0].details == {}  # the password failed, not the second factor
    # an address that is no account never reaches the log (it may be a password in the wrong field)
    assert "stranger" not in repr([(e.actor_email, e.details, e.subject) for e in entries])


def test_changing_the_password_is_in_the_log(client: FlaskClient, db_session: Session) -> None:
    user = create_user(db_session, "changer@example.org")  # password: Throwaway-Password-1
    login_as(client, user)
    response = client.post(
        "/auth/change-password",
        data={
            "password": "Throwaway-Password-1",
            "new_password": "Another-Throwaway-2",
            "new_password_confirm": "Another-Throwaway-2",
        },
    )
    assert response.status_code in (200, 302)
    (changed,) = audit_rows(db_session, "auth.password_changed")
    assert changed.actor_id == user.id


# ------------------------------------------------------------------------------ reading


def test_entries_come_newest_first_and_can_be_filtered(db_session: Session) -> None:
    ann, bob = (
        create_user(db_session, "ann@example.org"),
        create_user(db_session, "bob@example.org"),
    )
    first = create_assessment(db_session, ann, "first.example")
    second = create_assessment(db_session, bob, "second.example")
    day = timedelta(days=1)
    entry(db_session, "scan.started", NOW - 3 * day, actor=ann, assessment=first)
    entry(db_session, "export.json", NOW - 2 * day, actor=ann, assessment=first)
    entry(db_session, "finding.accepted", NOW - day, actor=bob, assessment=second)
    entry(db_session, "auth.login", NOW, actor=bob)

    def actions(**filters: object) -> list[str]:
        return [e.action for e in audit_service.list_events(db_session, **filters).items]  # type: ignore[arg-type]

    assert actions() == ["auth.login", "finding.accepted", "export.json", "scan.started"]
    assert actions(group="export") == ["export.json"]
    assert actions(action="finding.accepted") == ["finding.accepted"]
    assert (
        actions(group="nonsense", action="nonsense") == actions()
    )  # unknown choices filter nothing
    assert actions(actor="BOB") == ["auth.login", "finding.accepted"]
    assert actions(assessment_id=first.id) == ["export.json", "scan.started"]
    assert actions(since=NOW - day) == ["auth.login", "finding.accepted"]


def test_the_person_filter_takes_part_of_an_address_and_no_wildcards(db_session: Session) -> None:
    under, plain = (
        create_user(db_session, "a_b@example.org"),
        create_user(db_session, "axb@example.org"),
    )
    entry(db_session, actor=under)
    entry(db_session, actor=plain)
    found = audit_service.list_events(db_session, actor="a_b").items
    assert [e.actor_email for e in found] == ["a_b@example.org"]  # "_" is not "any character"
    assert audit_service.list_events(db_session, actor="%").total == 0


def test_a_long_log_is_paged(db_session: Session) -> None:
    for number in range(120):
        entry(db_session, "auth.login", NOW - timedelta(minutes=number))
    first = audit_service.list_events(db_session)
    last = audit_service.list_events(db_session, page=3)
    assert (first.total, first.pages, len(first.items)) == (120, 3, 50)
    assert len(last.items) == 20 and last.items[-1].occurred_at == NOW - timedelta(minutes=119)
    beyond = audit_service.list_events(db_session, page=99)  # past the end: the last page
    assert beyond.page == 3 and [e.id for e in beyond.items] == [e.id for e in last.items]
    assert audit_service.list_events(db_session, page=-4).page == 1
    assert audit_service.list_events(db_session, group="auth", page=9, per_page=500).per_page == 200


def test_an_entry_outlives_the_account_and_the_assessment(db_session: Session) -> None:
    owner = create_user(db_session, "leaver@example.org")
    assessment = create_assessment(db_session, owner, "gone.example")
    audit_service.record(db_session, "scan.started", actor=owner, assessment=assessment)
    db_session.delete(assessment)
    db_session.flush()
    db_session.delete(owner)
    db_session.flush()
    db_session.expire_all()

    (kept,) = audit_rows(db_session)
    assert kept.actor_id is None and kept.assessment_id is None  # the links are gone ...
    assert kept.actor_email == "leaver@example.org" and kept.details["domain"] == "gone.example"


# ------------------------------------------------------------------------------ retention


def test_entries_past_the_retention_period_are_removed(db_session: Session) -> None:
    entry(db_session, "auth.login", NOW - timedelta(days=800))
    entry(db_session, "auth.login", NOW - timedelta(days=731))
    keep = entry(db_session, "auth.login", NOW - timedelta(days=729))
    assert audit_service.purge(db_session, 0, now=NOW) == 0  # 0: keep everything
    assert audit_service.purge(db_session, 730, now=NOW) == 2
    assert audit_rows(db_session) == [keep]


def test_the_worker_removes_them_by_the_configured_period(db_session: Session) -> None:
    entry(db_session, "auth.login", datetime.now(UTC) - timedelta(days=400))
    recent = entry(db_session, "auth.login", datetime.now(UTC) - timedelta(days=2))
    worker_service.purge_audit_log(db_session, {"AUDIT_RETENTION_DAYS": 365})
    assert audit_rows(db_session) == [recent]
    worker_service.purge_audit_log(db_session, {"AUDIT_RETENTION_DAYS": 0})  # forever: nothing goes
    assert audit_rows(db_session) == [recent]


class BrokenCache:
    def purge(self, keep: timedelta) -> int:
        raise RuntimeError("the cache cannot be reached")


def test_housekeeping_that_fails_is_reported_and_does_not_stop_the_other_step(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    entry(db_session, "auth.login", datetime.now(UTC) - timedelta(days=900))
    with caplog.at_level(logging.ERROR, logger="app.service.worker"):
        worker_service.housekeeping(db_session, BrokenCache(), {"AUDIT_RETENTION_DAYS": 730})  # type: ignore[arg-type]
    assert audit_rows(db_session) == []  # the audit log was cleared although the cache was not
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == [
        "housekeeping: removing old provider-cache entries failed"
    ]


def test_a_worker_whose_housekeeping_cannot_run_still_takes_its_tasks(
    db_session: Session, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dev schema once lacked the audit table: that must not keep a scan from running."""

    def missing_table(session: Session, config: object) -> None:
        raise RuntimeError('relation "audit_event" does not exist')

    monkeypatch.setattr(worker_service, "purge_audit_log", missing_table)
    with caplog.at_level(logging.ERROR, logger="app.service.worker"):
        worker_service.housekeeping(db_session, BrokenCache(), {})  # type: ignore[arg-type]
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 2  # both are reported
    assert (
        db_session.execute(select(1)).scalar() == 1
    )  # ... and the session works for the next round


# ------------------------------------------------------------------------------ the page


def page(client: FlaskClient, query: str = "") -> str:
    response = client.get("/audit/" + query)
    assert response.status_code == 200, query
    return response.get_data(as_text=True)


def test_only_administrators_read_the_log(client: FlaskClient, db_session: Session) -> None:
    assert client.get("/audit/").status_code == 302  # not signed in: the login page
    login_as(client, create_user(db_session))
    assert client.get("/audit/").status_code == 404  # nothing here to confirm
    assert "Audit log" not in client.get("/assessments/").get_data(as_text=True)  # no link either
    login_as(client, admin(db_session))
    assert "Audit log" in client.get("/assessments/").get_data(as_text=True)
    assert "Entries" in page(client)


def test_the_page_lists_entries_with_who_what_which_assessment_and_from_where(
    client: FlaskClient, db_session: Session
) -> None:
    boss = admin(db_session)
    owner = create_user(db_session, "owner@example.org")
    assessment = create_assessment(db_session, owner, "vendor.example")
    entry(
        db_session,
        "finding.accepted",
        remote_addr="203.0.113.9",
        actor=owner,
        assessment=assessment,
        details={"rule": "SPF_MISSING"},
    )
    entry(
        db_session,
        "user.deactivated",
        NOW - timedelta(hours=1),
        details={"email": "leaver@example.org"},
    )
    login_as(client, boss)

    html = page(client)
    assert "Accepted a finding" in html and "owner@example.org" in html
    assert f'href="/assessments/{assessment.id}"' in html and "vendor.example" in html
    assert "203.0.113.9" in html and "SPF_MISSING" in html
    assert (
        "Switched an account off" in html
        and "command line" in html
        and "leaver@example.org" in html
    )
    assert html.index("Accepted a finding") < html.index("Switched an account off")  # newest first


def test_the_page_can_be_filtered_and_pages_keep_the_filter(
    client: FlaskClient, db_session: Session
) -> None:
    boss = admin(db_session)
    owner = create_user(db_session, "owner@example.org")
    assessment = create_assessment(db_session, owner, "vendor.example")
    db_session.execute(delete(AuditEvent))  # the set-up wrote entries of its own: count only ours
    now = datetime.now(UTC)
    for number in range(60):
        entry(
            db_session,
            "export.json",
            now - timedelta(minutes=number),
            remote_addr=EXPORT_ADDR,
            actor=owner,
            assessment=assessment,
        )
    entry(db_session, "auth.login", now - timedelta(days=40), remote_addr=LOGIN_ADDR, actor=owner)
    login_as(client, boss)

    # the drop-downs name every kind of entry, so the rows are told apart by where they came from
    everything = page(client)
    assert total(everything) == 61 and EXPORT_ADDR in everything
    auth_only = page(client, "?group=auth")
    assert total(auth_only) == 1 and LOGIN_ADDR in auth_only and EXPORT_ADDR not in auth_only
    assert total(page(client, "?group=export")) == 60
    assert total(page(client, f"?assessment={assessment.id}")) == 60  # the sign-in is no one's
    assert total(page(client, f"?assessment={assessment.id}&action=auth.login")) == 0
    recent = page(client, "?days=30")
    assert total(recent) == 60 and LOGIN_ADDR not in recent  # the sign-in is 40 days old
    assert total(page(client, "?days=90")) == 61

    second = page(client, "?group=export&page=2")
    assert "Page 2 of 2" in second and "Previous" in second and "Next" not in second
    assert 'href="/audit/?group=export"' in second  # the filter stays on the links, page 1 is bare
    assert "Page 1 of 2" in page(client, "?group=export") and "group=export&amp;page=2" in page(
        client, "?group=export"
    )

    assert "No entry matches." in page(client, "?user=nobody-like-this")
    assert total(page(client, "?user=OWNER@")) == 61
    junk = page(client, "?group=nonsense&action=nonsense&days=11&assessment=junk&page=x")
    assert total(junk) == 61 and not re.search(r"<option[^>]* selected", junk)  # filters nothing


def test_what_is_in_the_log_is_escaped_and_removed_assessments_are_named(
    client: FlaskClient, db_session: Session
) -> None:
    boss = admin(db_session)
    evil = '<img src=x onerror="alert(1)">'
    user = create_user(db_session, "<b>bold</b>@example.org")
    entry(
        db_session, "hosts.added", actor=user, details={"host": evil, "domain": "removed.example"}
    )
    login_as(client, boss)
    html = page(client)
    assert "<img src=x" not in html and "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html
    assert "<b>bold</b>" not in html and "&lt;b&gt;bold&lt;/b&gt;@example.org" in html
    assert (
        "removed.example" in html and "(removed)" in html
    )  # the assessment is gone, the name stays


# ------------------------------------------------------------------------------ the command


def test_the_log_can_be_read_on_the_command_line(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    result = cli_runner.invoke(args=["audit", "list"])
    assert result.exit_code == 0 and "no entry" in result.output

    owner = create_user(db_session, "owner@example.org")
    assessment = create_assessment(db_session, owner, "vendor.example")
    entry(db_session, "export.report", NOW, actor=owner, assessment=assessment)
    entry(db_session, "user.created", NOW - timedelta(days=3), details={"email": "new@example.org"})
    entry(
        db_session,
        "auth.login",
        NOW - timedelta(days=60),
        actor=owner,
        details={"via": ["password", "authenticator"]},
    )

    result = cli_runner.invoke(args=["audit", "list", "--limit", "10"])
    lines = result.output.splitlines()
    assert result.exit_code == 0 and lines[-1] == "3 of 3 entries."
    assert (
        "owner@example.org" in lines[0]
        and "Opened the report" in lines[0]
        and "[vendor.example]" in lines[0]
    )
    assert "command line" in lines[1] and "email=new@example.org" in lines[1]

    only_export = cli_runner.invoke(args=["audit", "list", "--group", "export"]).output
    assert "Opened the report" in only_export and "Created an account" not in only_export
    recent = cli_runner.invoke(args=["audit", "list", "--days", "30"]).output
    assert "Signed in" not in recent and recent.splitlines()[-1] == "2 of 2 entries."
    by_person = cli_runner.invoke(args=["audit", "list", "--user", "OWNER@"]).output
    assert "Created an account" not in by_person and "Signed in" in by_person
    assert "via=password, authenticator" in by_person  # a list is text, not Python
    assert cli_runner.invoke(args=["audit", "list", "--group", "nonsense"]).exit_code != 0


def test_facts_are_plain_text_without_the_domain_and_the_empty() -> None:
    shown = audit_service.facts(
        {
            "domain": "x.example",
            "hosts": ["a", "b"],
            "limit": 3,
            "blank": "",
            "none": [],
            "ok": True,
        }
    )
    assert shown == [("hosts", "a, b"), ("limit", "3"), ("ok", "True")]


def test_every_audited_action_has_words() -> None:
    """A code the page cannot put into words would be shown raw: keep the two lists in step."""
    assert set(audit_service.ACTIONS) >= {
        "auth.login", "scan.started", "scan.refused", "export.report", "finding.reopened",
        "user.mfa_reset", "assessment.shared", "hosts.added",
    }  # fmt: skip
    for code in audit_service.ACTIONS:
        assert code.split(".")[0] in audit_service.GROUPS, code
        assert audit_service.action_label(code) != code
    assert audit_service.action_label("nobody.knows") == "nobody.knows"
