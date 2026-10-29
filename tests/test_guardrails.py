"""Guardrails: the scan rate limit per person, the host cap and the settings that set them."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import create_app
from app.config import (
    MAX_HOSTS_CEILING,
    ConfigurationError,
    TestingConfig,
    validate_config,
)
from app.models import Scan, User
from app.models.base import utc_now
from app.service import scans as scan_service
from tests.helpers import audit_rows, create_assessment, create_user, login_as
from tests.test_engine import CONFIG, FakeCheck, discovery, drain, hosts_of

LIMITED = {**CONFIG, "MAX_SCANS_PER_USER_PER_HOUR": 3}


def start(
    session: Session, user: User, config: dict[str, Any], age: timedelta | None = None
) -> Scan:
    """Start a scan of a new assessment, as if it had been started ``age`` ago."""
    assessment = create_assessment(session, user, f"d{uuid.uuid4().hex[:10]}.example")
    scan = scan_service.start_scan(session, assessment, user, config)
    if age is not None:
        scan.created_at = utc_now() - age
    session.commit()
    return scan


# ------------------------------------------------------------------------------ scan rate limit


def test_a_person_may_start_the_allowed_number_of_scans_an_hour_and_no_more(
    db_session: Session,
) -> None:
    user = create_user(db_session)
    for _ in range(3):
        start(db_session, user, LIMITED)
    refused = create_assessment(db_session, user, "refused.example")

    with pytest.raises(scan_service.ScanRateLimitError) as raised:
        scan_service.start_scan(db_session, refused, user, LIMITED)

    assert raised.value.limit == 3
    assert timedelta(minutes=59) < raised.value.retry_after <= timedelta(hours=1)
    assert db_session.scalars(select(Scan).where(Scan.assessment_id == refused.id)).all() == []


def test_the_wait_is_until_enough_of_the_hours_scans_are_an_hour_old(db_session: Session) -> None:
    user = create_user(db_session)
    for age in (50, 30, 10):
        start(db_session, user, CONFIG, age=timedelta(minutes=age))
    target = create_assessment(db_session, user, "wait.example")

    def wait(limit: int) -> timedelta:
        with pytest.raises(scan_service.ScanRateLimitError) as raised:
            scan_service.start_scan(
                db_session, target, user, {**CONFIG, "MAX_SCANS_PER_USER_PER_HOUR": limit}
            )
        return raised.value.retry_after

    # limit 3: the oldest (50 minutes old) must leave the hour: 10 minutes. Limit 2: the two oldest
    # must: 30 minutes. Limit 1: all three must: 50 minutes.
    assert timedelta(minutes=9) < wait(3) <= timedelta(minutes=10)
    assert timedelta(minutes=29) < wait(2) <= timedelta(minutes=30)
    assert timedelta(minutes=49) < wait(1) <= timedelta(minutes=50)


def test_scans_older_than_an_hour_and_other_peoples_scans_do_not_count(db_session: Session) -> None:
    busy, other = create_user(db_session), create_user(db_session)
    for age in (61, 90, 600):
        start(db_session, busy, LIMITED, age=timedelta(minutes=age))
    for _ in range(3):
        start(db_session, other, LIMITED)

    assert start(db_session, busy, LIMITED).status == "queued"  # theirs are all past the hour
    with pytest.raises(scan_service.ScanRateLimitError):
        start(db_session, other, LIMITED)  # but the other person has used their three


@pytest.mark.parametrize("config", [{**CONFIG, "MAX_SCANS_PER_USER_PER_HOUR": 0}, CONFIG])
def test_no_limit_means_no_limit(db_session: Session, config: dict[str, Any]) -> None:
    user = create_user(db_session)
    scans = [start(db_session, user, config) for _ in range(8)]
    assert len(scans) == 8


def test_the_refusal_comes_after_the_check_for_a_running_scan(db_session: Session) -> None:
    """One question at a time: a scan already running says so, whatever the person's count."""
    user = create_user(db_session)
    for _ in range(3):
        start(db_session, user, LIMITED)
    running = db_session.scalars(select(Scan)).first()
    assert running is not None
    with pytest.raises(scan_service.ScanInProgressError):
        scan_service.start_scan(db_session, running.assessment, user, LIMITED)


def test_the_page_tells_when_the_next_scan_can_start_and_the_refusal_is_audited(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "MAX_SCANS_PER_USER_PER_HOUR", 1)
    user = create_user(db_session)
    first = create_assessment(db_session, user, "first.example")
    second = create_assessment(db_session, user, "second.example")
    login_as(client, user)

    assert client.post(f"/assessments/{first.id}/scans").status_code == 302
    response = client.post(f"/assessments/{second.id}/scans", follow_redirects=True)
    page = response.get_data(as_text=True)

    assert "You have started the most scans allowed in an hour (1)." in page
    assert re.search(r"can start in about (59|60) minutes", page)
    assert db_session.scalars(select(Scan).where(Scan.assessment_id == second.id)).all() == []
    (refused,) = audit_rows(db_session, "scan.refused")
    assert (refused.actor_id, refused.assessment_id) == (user.id, second.id)
    assert refused.details["limit"] == 1
    assert len(audit_rows(db_session, "scan.started")) == 1  # only the first one went ahead


def test_the_defaults_are_twenty_scans_an_hour_and_two_years_of_audit_log(app: Flask) -> None:
    assert app.config["MAX_SCANS_PER_USER_PER_HOUR"] == 20
    assert app.config["AUDIT_RETENTION_DAYS"] == 730


# ------------------------------------------------------------------------------ host cap


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, 200),
        ({"max_hosts": 50}, 50),
        ({"max_hosts": 2000}, 2000),
        ({"max_hosts": 2001}, 2000),
        ({"max_hosts": 10**9}, 2000),
        ({"max_hosts": 0}, 1),
        ({"max_hosts": -5}, 1),
        ({"max_hosts": "30"}, 30),
        ({"max_hosts": "lots"}, 200),
        ({"max_hosts": None}, 200),
    ],
)
def test_a_scan_reviews_at_least_one_host_and_never_more_than_the_ceiling(
    options: dict[str, Any], expected: int
) -> None:
    assert scan_service.host_cap(options) == expected


def test_a_scan_is_started_with_the_configured_cap_but_never_above_the_ceiling(
    db_session: Session,
) -> None:
    user = create_user(db_session)
    assert start(db_session, user, {**CONFIG, "MAX_HOSTS_PER_RUN": 40}).options["max_hosts"] == 40
    too_many = {**CONFIG, "MAX_HOSTS_PER_RUN": 5000}  # a mapping that skipped the validation
    assert start(db_session, user, too_many).options["max_hosts"] == MAX_HOSTS_CEILING


def test_the_ceiling_holds_for_a_scan_that_was_stored_with_a_larger_cap(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What was stored is not trusted: the planner clamps it, so no row can lift the limit."""
    monkeypatch.setattr(scan_service, "MAX_HOSTS_CEILING", 4)
    user = create_user(db_session)
    scan = start(db_session, user, CONFIG)
    scan.options = {**scan.options, "max_hosts": 100}
    db_session.commit()
    names = [f"h{n}.{scan.assessment.domain}" for n in range(10)]
    registry = {"discovery": discovery(*names), "fake_host": FakeCheck("fake_host", "host")}

    drain(db_session, registry)

    assert len(hosts_of(db_session, scan)) == 4
    row = scan_service.get_discovery(db_session, scan)
    assert row is not None and row.data["planned"] == {"hosts": 4, "dropped_by_cap": 7}


def test_the_cap_keeps_the_apex_then_the_manual_hosts_then_what_the_certificates_found() -> None:
    data = {
        "hosts": [
            {
                "hostname": f"ct{n}.example.com",
                "sources": ["ctlogs"],
                "first_seen": None,
                "last_seen": None,
            }
            for n in range(5)
        ]
    }
    seeds, dropped = scan_service.plan_hosts(
        "example.com", data, True, ["vpn.example.com", "mail.example.com"], 4
    )
    assert [(s.hostname, s.source) for s in seeds] == [
        ("example.com", "apex"),
        ("vpn.example.com", "manual"),
        ("mail.example.com", "manual"),
        ("ct0.example.com", "ct"),
    ]
    assert dropped == 4


# ------------------------------------------------------------------------------ the settings


def config_with(**values: Any) -> type[TestingConfig]:
    return type("Changed", (TestingConfig,), values)


def test_the_host_cap_setting_may_not_exceed_the_ceiling() -> None:
    validate_config(config_with(MAX_HOSTS_PER_RUN=MAX_HOSTS_CEILING))
    with pytest.raises(ConfigurationError, match="MAX_HOSTS_PER_RUN may not exceed 2000"):
        validate_config(config_with(MAX_HOSTS_PER_RUN=MAX_HOSTS_CEILING + 1))
    with pytest.raises(ConfigurationError, match="MAX_HOSTS_PER_RUN must be a positive integer"):
        validate_config(config_with(MAX_HOSTS_PER_RUN=0))


@pytest.mark.parametrize(
    ("setting", "good", "bad"),
    [
        ("MAX_SCANS_PER_USER_PER_HOUR", (0, 1, 1000), (-1, 1001, True, 2.5, "20")),
        ("AUDIT_RETENTION_DAYS", (0, 1, 3650), (-1, 3651, True, 30.0, "730")),
    ],
)
def test_the_new_limits_are_whole_numbers_within_their_range(
    setting: str, good: tuple[int, ...], bad: tuple[object, ...]
) -> None:
    for value in good:
        validate_config(config_with(**{setting: value}))
    for value in bad:
        with pytest.raises(ConfigurationError, match=f"{setting} must be an integer from 0 to"):
            validate_config(config_with(**{setting: value}))


def test_an_invitation_link_works_for_72_hours_by_default(app: Flask) -> None:
    assert app.config["INVITATION_HOURS"] == 72


@pytest.mark.parametrize(("good", "bad"), [((1, 72, 168), (0, 169, -5, True, 12.5, "72"))])
def test_the_invitation_hours_are_a_whole_number_from_1_to_168(
    good: tuple[int, ...], bad: tuple[object, ...]
) -> None:
    for value in good:
        validate_config(config_with(INVITATION_HOURS=value))
    for value in bad:
        with pytest.raises(
            ConfigurationError, match="INVITATION_HOURS must be an integer from 1 to 168"
        ):
            validate_config(config_with(INVITATION_HOURS=value))


def test_the_environment_sets_the_invitation_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_SCHEMA", "")
    monkeypatch.setenv("INVITATION_HOURS", "24")
    assert create_app("development").config["INVITATION_HOURS"] == 24

    monkeypatch.setenv("INVITATION_HOURS", "soon")
    with pytest.raises(ConfigurationError, match="INVITATION_HOURS must be an integer"):
        create_app("development")
    monkeypatch.setenv("INVITATION_HOURS", "0")
    with pytest.raises(ConfigurationError, match="INVITATION_HOURS must be an integer from 1"):
        create_app("development")


def test_the_environment_sets_the_limits_and_a_wrong_value_stops_the_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DB_SCHEMA", "")
    monkeypatch.setenv("MAX_SCANS_PER_USER_PER_HOUR", "7")
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("MAX_HOSTS_PER_RUN", "1500")
    app = create_app("development")
    assert app.config["MAX_SCANS_PER_USER_PER_HOUR"] == 7
    assert app.config["AUDIT_RETENTION_DAYS"] == 90
    assert app.config["MAX_HOSTS_PER_RUN"] == 1500

    monkeypatch.setenv("MAX_HOSTS_PER_RUN", "5000")
    with pytest.raises(ConfigurationError, match="MAX_HOSTS_PER_RUN may not exceed 2000"):
        create_app("development")
    monkeypatch.setenv("MAX_HOSTS_PER_RUN", "200")
    monkeypatch.setenv("MAX_SCANS_PER_USER_PER_HOUR", "many")
    with pytest.raises(ConfigurationError, match="MAX_SCANS_PER_USER_PER_HOUR must be an integer"):
        create_app("development")
    monkeypatch.setenv("MAX_SCANS_PER_USER_PER_HOUR", "-3")
    with pytest.raises(
        ConfigurationError, match="MAX_SCANS_PER_USER_PER_HOUR must be an integer from 0"
    ):
        create_app("development")
