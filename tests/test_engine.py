"""The scan engine: discovery expands into hosts, checks run, failures stay visible."""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from flask_migrate import upgrade
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckContext, CheckOutcome
from app.extensions import db
from app.models import CheckResult, Host, Scan
from app.models.base import utc_now
from app.service import scans as scan_service
from app.service import worker
from tests.helpers import MIGRATIONS_DIRECTORY, create_assessment, create_user, make_app

CONFIG: dict[str, Any] = {
    "MAX_HOSTS_PER_RUN": 200,
    "CT_MODE": "union",
    "CT_SOURCES": ["ctlogs"],
    "MAX_DISCOVERY_PAGES": 5,
}


class FakeCheck:
    """A check that records its calls and returns a canned outcome (or raises)."""

    def __init__(
        self,
        key: str,
        scope: str,
        outcome: CheckOutcome | None = None,
        needs: tuple[str, ...] = (),
        raises: Exception | None = None,
    ) -> None:
        self.key = key
        self.scope = scope
        self.needs = needs
        self.outcome = outcome
        self.raises = raises
        self.calls: list[str] = []

    def run(self, ctx: CheckContext) -> CheckOutcome:
        self.calls.append(ctx.hostname or ctx.domain)
        if self.raises is not None:
            raise self.raises
        return self.outcome or CheckOutcome("ok", data={"hostname": ctx.hostname})


def discovery_data(*hostnames: str) -> dict[str, Any]:
    return {
        "hosts": [
            {"hostname": name, "first_seen": None, "last_seen": None, "sources": ["ctlogs"]}
            for name in hostnames
        ],
        "wildcard_patterns": [],
        "counts": {"hosts": len(hostnames)},
        "sources": [{"source": "ctlogs", "status": "ok"}],
    }


def discovery(*hostnames: str, outcome: CheckOutcome | None = None) -> FakeCheck:
    return FakeCheck(
        "discovery", "domain", outcome or CheckOutcome("ok", data=discovery_data(*hostnames))
    )


def drain(session: Session, registry: dict[str, Any], config: dict[str, Any] = CONFIG) -> int:
    """Run tasks until the queue is empty; return how many ran."""
    http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))
    done = 0
    while worker.process_one(session, "w1", config=config, http=http, registry=registry):
        done += 1
        assert done < 500, "the queue never drained"
    return done


def new_scan(session: Session, domain: str = "example.com", **assessment_fields: Any) -> Scan:
    user = create_user(session)
    assessment = create_assessment(session, user, domain)
    for name, value in assessment_fields.items():
        setattr(assessment, name, value)
    scan = scan_service.start_scan(session, assessment, user, CONFIG)
    session.commit()
    return scan


def hosts_of(session: Session, scan: Scan) -> list[Host]:
    return list(
        session.scalars(select(Host).where(Host.scan_id == scan.id).order_by(Host.hostname))
    )


# ------------------------------------------------------------------------------ lifecycle


def test_starting_a_scan_queues_discovery_and_refuses_a_second_active_scan(
    db_session: Session,
) -> None:
    scan = new_scan(db_session)
    queued = db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)).all()
    assert [(c.check_key, c.host_id, c.status) for c in queued] == [("discovery", None, "queued")]
    assert scan.status == "queued" and scan.options["max_hosts"] == 200

    assessment = scan.assessment
    with pytest.raises(scan_service.ScanInProgressError) as raised:
        scan_service.start_scan(db_session, assessment, create_user(db_session), CONFIG)
    assert raised.value.scan.id == scan.id


def test_a_scan_runs_discovery_then_the_host_checks_and_completes(db_session: Session) -> None:
    scan = new_scan(db_session)
    host_check = FakeCheck("fake_host", "host")
    registry = {
        "discovery": discovery("www.example.com", "api.example.com"),
        "fake_host": host_check,
    }

    assert drain(db_session, registry) == 1 + 3  # discovery + three hosts
    db_session.refresh(scan)

    hosts = hosts_of(db_session, scan)
    assert [h.hostname for h in hosts] == ["api.example.com", "example.com", "www.example.com"]
    # The apex is always reviewed, even though no certificate named it.
    assert {h.hostname: h.source for h in hosts}["example.com"] == "apex"
    assert sorted(host_check.calls) == [h.hostname for h in hosts]
    assert scan.status == "completed"
    assert scan.started_at is not None and scan.finished_at is not None
    progress = scan_service.scan_progress(db_session, scan)
    assert (progress.hosts, progress.checks_total, progress.checks_open, progress.percent) == (
        3,
        4,
        0,
        100,
    )


def test_when_every_source_fails_the_scan_falls_back_to_apex_and_www_and_is_partial(
    db_session: Session,
) -> None:
    scan = new_scan(db_session)
    failed = CheckOutcome(
        "error", "all_sources_failed", data={"hosts": [], "sources": [{"status": "error"}]}
    )
    registry = {"discovery": discovery(outcome=failed), "fake_host": FakeCheck("fake_host", "host")}

    drain(db_session, registry)
    db_session.refresh(scan)

    assert {h.hostname: h.source for h in hosts_of(db_session, scan)} == {
        "example.com": "apex",
        "www.example.com": "fallback",
    }
    assert scan.status == "partial"  # the failed discovery stays visible in the scan result


def test_manual_hosts_join_the_scan_and_the_cap_drops_ct_hosts_first(db_session: Session) -> None:
    config = {**CONFIG, "MAX_HOSTS_PER_RUN": 3}
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "example.com")
    assessment.manual_hosts = ["vpn.example.com"]
    scan = scan_service.start_scan(db_session, assessment, user, config)
    db_session.commit()
    names = [f"h{i}.example.com" for i in range(5)]
    registry = {"discovery": discovery(*names), "fake_host": FakeCheck("fake_host", "host")}

    drain(db_session, registry, config)
    db_session.refresh(scan)

    kept = {h.hostname: h.source for h in hosts_of(db_session, scan)}
    assert kept == {"example.com": "apex", "vpn.example.com": "manual", "h0.example.com": "ct"}
    row = scan_service.get_discovery(db_session, scan)
    assert row is not None and row.data["planned"] == {"hosts": 3, "dropped_by_cap": 4}


def test_a_check_whose_prerequisite_failed_is_skipped_with_the_reason(db_session: Session) -> None:
    scan = new_scan(db_session)
    needy = FakeCheck("needy", "host", needs=("fake_host",))
    registry = {
        "discovery": discovery(),
        "fake_host": FakeCheck("fake_host", "host", CheckOutcome("error", "boom")),
        "needy": needy,
    }
    drain(db_session, registry)

    skipped = db_session.scalars(select(CheckResult).where(CheckResult.check_key == "needy")).one()
    assert (skipped.status, skipped.reason_code) == ("skipped", "needs:fake_host")
    assert needy.calls == []
    db_session.refresh(scan)
    assert scan.status == "partial"


def test_a_crashing_check_becomes_an_error_outcome_without_leaking_details(
    db_session: Session,
) -> None:
    scan = new_scan(db_session)
    registry = {
        "discovery": discovery(),
        "fake_host": FakeCheck("fake_host", "host", raises=RuntimeError("secret internal detail")),
    }
    drain(db_session, registry)

    row = db_session.scalars(select(CheckResult).where(CheckResult.check_key == "fake_host")).one()
    assert (row.status, row.reason_code, row.data) == ("error", "internal_error", {})
    db_session.refresh(scan)
    assert scan.status == "partial"


def test_unknown_checks_are_errors_not_crashes(db_session: Session) -> None:
    scan = new_scan(db_session)
    registry: dict[str, Any] = {"discovery": discovery()}
    db_session.add(CheckResult(scan_id=scan.id, host_id=None, check_key="removed_check"))
    db_session.commit()
    drain(db_session, registry)
    row = db_session.scalars(
        select(CheckResult).where(CheckResult.check_key == "removed_check")
    ).one()
    assert (row.status, row.reason_code) == ("error", "unknown_check")


# ------------------------------------------------------------------------------ crash safety


def test_a_stale_lock_is_requeued_and_the_late_result_of_the_old_worker_is_discarded(
    db_session: Session,
) -> None:
    new_scan(db_session)
    registry: dict[str, Any] = {"discovery": discovery("a.example.com")}
    now = utc_now()

    task = worker.claim_next(db_session, "worker-a", now)
    assert task is not None and task.status == "running" and task.attempts == 1
    task.locked_at = now - worker.STALE_LOCK - timedelta(seconds=1)  # worker A hangs or dies
    db_session.commit()

    assert worker.requeue_stale(db_session, utc_now()) == 1
    db_session.refresh(task)
    assert (task.status, task.locked_by) == ("queued", None)

    second = worker.claim_next(db_session, "worker-b", utc_now())
    assert second is not None and second.id == task.id and second.attempts == 2

    late = CheckOutcome("ok", data=discovery_data("stale.example.com"))
    assert worker._store_outcome(db_session, task, "worker-a", late, 5, registry) is False
    fresh = CheckOutcome("ok", data=discovery_data("a.example.com"))
    assert worker._store_outcome(db_session, second, "worker-b", fresh, 5, registry) is True

    hosts = {h.hostname for h in db_session.scalars(select(Host))}
    assert "stale.example.com" not in hosts and "a.example.com" in hosts


def test_tasks_that_keep_failing_end_as_errors_and_finish_the_scan(db_session: Session) -> None:
    scan = new_scan(db_session)
    task = worker.claim_next(db_session, "worker-a", utc_now())
    assert task is not None
    task.attempts = worker.MAX_ATTEMPTS
    task.locked_at = utc_now() - worker.STALE_LOCK - timedelta(seconds=1)
    db_session.commit()

    assert worker.requeue_stale(db_session, utc_now()) == 1
    db_session.refresh(task)
    db_session.refresh(scan)
    assert (task.status, task.reason_code) == ("error", "max_attempts_exceeded")
    assert scan.status == "partial"


# ------------------------------------------------------------------------------ hosts and progress


def test_host_listing_is_paged_and_searched_in_sql_with_literal_wildcards(
    db_session: Session,
) -> None:
    scan = new_scan(db_session)
    db_session.add_all([Host(scan_id=scan.id, hostname=f"h{i:02}.example.com") for i in range(7)])
    db_session.add(Host(scan_id=scan.id, hostname="special.example.com"))
    db_session.commit()

    first = scan_service.list_hosts(db_session, scan.id, per_page=3)
    assert (first.total, first.pages, [h.hostname for h in first.rows]) == (
        8,
        3,
        ["h00.example.com", "h01.example.com", "h02.example.com"],
    )
    assert [
        h.hostname for h in scan_service.list_hosts(db_session, scan.id, page=3, per_page=3).rows
    ] == [
        "h06.example.com",
        "special.example.com",
    ]
    assert scan_service.list_hosts(db_session, scan.id, query="SPECIAL").total == 1
    assert scan_service.list_hosts(db_session, scan.id, query="%").total == 0  # not a wildcard
    assert scan_service.list_hosts(db_session, scan.id, query="h_0").total == 0  # nor is "_"


def test_a_new_scan_is_allowed_once_the_previous_one_finished(db_session: Session) -> None:
    scan = new_scan(db_session)
    drain(db_session, {"discovery": discovery()})
    db_session.refresh(scan)
    assert scan.is_terminal
    again = scan_service.start_scan(db_session, scan.assessment, create_user(db_session), CONFIG)
    assert again.id != scan.id and again.status == "queued"


# ------------------------------------------------------------------------------ concurrency


def _concurrent_app(database_url: str) -> tuple[Any, str]:
    schema = f"t_{uuid.uuid4().hex[:12]}"
    app = make_app(database_url, schema)
    with app.app_context():
        upgrade(directory=str(MIGRATIONS_DIRECTORY))
    return app, schema


def _drop(database_url: str, schema: str, app: Any) -> None:
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    engine = sa.create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    engine.dispose()


def test_concurrent_workers_claim_every_task_exactly_once(database_url: str) -> None:
    app, schema = _concurrent_app(database_url)
    try:
        with app.app_context():
            user = create_user(db.session())
            assessment = create_assessment(db.session(), user)
            scan = scan_service.start_scan(db.session(), assessment, user, CONFIG)
            for number in range(60):
                db.session.add(CheckResult(scan_id=scan.id, host_id=None, check_key=f"c{number}"))
            db.session.commit()

        claimed: list[list[str]] = [[] for _ in range(6)]

        def work(index: int) -> None:
            with app.app_context():
                session = db.session()
                while (task := worker.claim_next(session, f"w{index}", utc_now())) is not None:
                    claimed[index].append(task.check_key)
                db.session.remove()

        threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        everything = [key for part in claimed for key in part]
        expected = ["discovery", *(f"c{n}" for n in range(60))]
        assert sorted(everything) == sorted(expected)  # none lost, none claimed twice
    finally:
        _drop(database_url, schema, app)


def test_the_last_two_checks_finishing_together_always_finalise_the_scan(
    database_url: str,
) -> None:
    app, schema = _concurrent_app(database_url)
    try:
        for _ in range(12):
            with app.app_context():
                user = create_user(db.session())
                assessment = create_assessment(db.session(), user, f"d{uuid.uuid4().hex[:6]}.test")
                scan = Scan(assessment_id=assessment.id, requested_by=user.id, status="running")
                db.session.add(scan)
                db.session.flush()
                rows = [
                    CheckResult(
                        scan_id=scan.id, check_key=key, status="running", locked_by=key, attempts=1
                    )
                    for key in ("one", "two")
                ]
                db.session.add_all(rows)
                db.session.commit()
                scan_id, row_ids = scan.id, [row.id for row in rows]

            barrier = threading.Barrier(2)

            def finish(row_id: uuid.UUID, key: str, barrier: threading.Barrier = barrier) -> None:
                with app.app_context():
                    session = db.session()
                    task = session.get(CheckResult, row_id)
                    barrier.wait(timeout=10)
                    worker._store_outcome(session, task, key, CheckOutcome("ok"), 1, {})
                    db.session.remove()

            threads = [
                threading.Thread(target=finish, args=(row_id, key))
                for row_id, key in zip(row_ids, ("one", "two"), strict=True)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

            with app.app_context():
                final = db.session.get(Scan, scan_id)
                assert final is not None and final.status == "completed", "scan stayed unfinished"
                assert final.finished_at is not None
                db.session.remove()
    finally:
        _drop(database_url, schema, app)


def test_the_worker_command_exits_cleanly_on_an_empty_queue(cli_runner: Any) -> None:
    result = cli_runner.invoke(args=["worker", "--once"])
    assert result.exit_code == 0, result.output
    assert "Processed 0 task(s)." in result.output
