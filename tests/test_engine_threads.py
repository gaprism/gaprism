"""The threaded worker: dependencies between checks, the per-target limit, cancel."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checks.base import CheckContext, CheckOutcome
from app.extensions import db
from app.models import CheckResult, Scan
from app.models.base import utc_now
from app.service import scans as scan_service
from app.service import worker
from tests.helpers import create_assessment, create_user
from tests.test_engine import (
    CONFIG,
    FakeCheck,
    _concurrent_app,
    _drop,
    discovery,
    discovery_data,
    drain,
    hosts_of,
    new_scan,
)


def offline_client() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))


def run_next(session: Session, registry: dict[str, Any], name: str = "w") -> CheckResult | None:
    """Claim and fully run one task; return it (or ``None`` when nothing may run)."""
    task = worker.claim_next(session, name, utc_now(), registry=registry)
    if task is not None:
        worker.execute_task(
            session, task, name, config=CONFIG, http=offline_client(), registry=registry
        )
    return task


# ------------------------------------------------------------------------------ dependencies


def test_a_task_waits_until_the_checks_it_needs_are_finished(db_session: Session) -> None:
    new_scan(db_session)
    registry: dict[str, Any] = {
        "discovery": discovery("a.example.com"),
        "first": FakeCheck("first", "host"),
        "second": FakeCheck("second", "host", needs=("first",)),
    }
    run_next(db_session, registry)  # discovery creates two hosts with both checks each

    one = worker.claim_next(db_session, "w1", utc_now(), registry=registry)
    two = worker.claim_next(db_session, "w2", utc_now(), registry=registry)
    assert one is not None and two is not None
    assert (one.check_key, two.check_key) == ("first", "first")  # never a "second" before "first"
    assert one.host_id != two.host_id
    # Both "second" tasks are queued but blocked by their running prerequisite.
    assert worker.claim_next(db_session, "w3", utc_now(), registry=registry) is None

    worker._store_outcome(db_session, one, "w1", CheckOutcome("ok"), 1, registry)
    unblocked = worker.claim_next(db_session, "w3", utc_now(), registry=registry)
    assert unblocked is not None
    assert (unblocked.check_key, unblocked.host_id) == ("second", one.host_id)  # only its own host
    assert worker.claim_next(db_session, "w4", utc_now(), registry=registry) is None


def test_a_failed_prerequisite_unblocks_its_dependent_as_skipped(db_session: Session) -> None:
    new_scan(db_session)
    registry: dict[str, Any] = {
        "discovery": discovery(),
        "first": FakeCheck("first", "host", CheckOutcome("error", "boom")),
        "second": FakeCheck("second", "host", needs=("first",)),
    }
    drain(db_session, registry)
    row = db_session.scalars(select(CheckResult).where(CheckResult.check_key == "second")).one()
    assert (row.status, row.reason_code) == ("skipped", "needs:first")


# ------------------------------------------------------------------------------ limits


def test_scans_at_their_limit_are_passed_over(db_session: Session) -> None:
    older = new_scan(db_session, "older.example.org")
    newer = new_scan(db_session, "newer.example.org")
    registry: dict[str, Any] = {"discovery": discovery()}

    task = worker.claim_next(
        db_session, "w", utc_now(), registry=registry, exclude_scans={older.id}
    )
    assert task is not None and task.scan_id == newer.id
    assert (
        worker.claim_next(
            db_session, "w", utc_now(), registry=registry, exclude_scans={older.id, newer.id}
        )
        is None
    )
    free = worker.claim_next(db_session, "w", utc_now(), registry=registry)
    assert free is not None and free.scan_id == older.id


def test_the_target_limiter_counts_running_tasks_per_scan() -> None:
    limiter = worker.TargetLimiter(2)
    a, b = uuid.uuid4(), uuid.uuid4()
    assert limiter.full() == frozenset() and limiter.active == 0
    limiter.enter(a)
    assert limiter.full() == frozenset()
    limiter.enter(a)
    limiter.enter(b)
    assert limiter.full() == {a} and limiter.active == 3
    limiter.leave(a)
    assert limiter.full() == frozenset() and limiter.active == 2
    limiter.leave(a)
    limiter.leave(b)
    assert limiter.active == 0
    with pytest.raises(ValueError, match="at least 1"):
        worker.TargetLimiter(0)


# ------------------------------------------------------------------------------ cancel


def test_cancelling_skips_queued_checks_and_ends_the_scan(db_session: Session) -> None:
    scan = new_scan(db_session)
    registry: dict[str, Any] = {
        "discovery": discovery("a.example.com", "b.example.com"),
        "fake_host": FakeCheck("fake_host", "host"),
    }
    run_next(db_session, registry)  # discovery: three hosts, three queued checks
    run_next(db_session, registry)  # one host check finishes

    assert scan_service.cancel_active_scan(db_session, scan.assessment_id) is True
    db_session.commit()
    db_session.refresh(scan)

    assert scan.status == "cancelled" and scan.finished_at is not None
    statuses = sorted(
        (row.status, row.reason_code)
        for row in db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id))
    )
    assert statuses == [
        ("ok", None),  # discovery
        ("ok", None),  # the host check that had finished
        ("skipped", "scan_cancelled"),
        ("skipped", "scan_cancelled"),
    ]
    assert drain(db_session, registry) == 0  # nothing is left to claim
    assert scan_service.cancel_active_scan(db_session, scan.assessment_id) is False  # already over

    # A new scan is possible right away.
    again = scan_service.start_scan(db_session, scan.assessment, create_user(db_session), CONFIG)
    assert again.status == "queued"


def test_a_scan_cancelled_while_discovery_runs_gets_no_hosts(db_session: Session) -> None:
    scan = new_scan(db_session)

    class CancellingDiscovery(FakeCheck):
        def run(self, ctx: CheckContext) -> CheckOutcome:
            scan_service.cancel_active_scan(db_session, scan.assessment_id)
            db_session.commit()
            return super().run(ctx)

    registry: dict[str, Any] = {
        "discovery": CancellingDiscovery(
            "discovery", "domain", CheckOutcome("ok", data=discovery_data("a.example.com"))
        ),
        "fake_host": FakeCheck("fake_host", "host"),
    }
    run_next(db_session, registry)
    db_session.refresh(scan)

    assert scan.status == "cancelled"
    assert hosts_of(db_session, scan) == []
    row = scan_service.get_discovery(db_session, scan)
    assert row is not None and row.status == "ok"  # what discovery found is kept
    assert db_session.scalar(select(func.count()).select_from(CheckResult)) == 1


# ------------------------------------------------------------------------------ threads


class Probe:
    """A host check that measures how many copies run at once."""

    scope = "host"
    needs: tuple[str, ...] = ()

    def __init__(self, key: str = "probe", hold: float = 0.03, rendezvous: int = 0) -> None:
        self.key = key
        self.hold = hold
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.started = 0
        self.barrier = threading.Barrier(rendezvous) if rendezvous else None
        self.rendezvous = rendezvous

    def run(self, ctx: CheckContext) -> CheckOutcome:
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.started += 1
            first_wave = self.started <= self.rendezvous
        try:
            if first_wave and self.barrier is not None:
                self.barrier.wait(timeout=10)  # proves that this many really run together
            time.sleep(self.hold)
        finally:
            with self.lock:
                self.active -= 1
        return CheckOutcome("ok")


def start_scan_for(app: Any, domain: str = "example.com") -> Any:
    with app.app_context():
        user = create_user(db.session())
        assessment = create_assessment(db.session(), user, domain)
        scan = scan_service.start_scan(db.session(), assessment, user, CONFIG)
        db.session.commit()
        scan_id = scan.id
        db.session.remove()
    return scan_id


def test_eight_threads_finish_a_large_scan_once_each_and_respect_the_target_limit(
    database_url: str,
) -> None:
    app, schema = _concurrent_app(database_url)
    try:
        scan_id = start_scan_for(app)
        names = [f"h{n:02}.example.com" for n in range(60)]
        probe = Probe(rendezvous=4)
        registry: dict[str, Any] = {"discovery": discovery(*names), "probe": probe}

        processed = worker.run_worker(app, once=True, threads=8, registry=registry)

        assert probe.max_active == 4  # four at once (the barrier proves it), never more
        with app.app_context():
            rows = db.session.scalars(
                select(CheckResult).where(CheckResult.scan_id == scan_id)
            ).all()
            assert len(rows) == 1 + 61  # discovery + one probe per host (60 + the apex)
            assert {row.status for row in rows} == {"ok"}
            assert {row.attempts for row in rows} == {1}  # nothing ran twice
            assert processed == len(rows)
            scan = db.session.get(Scan, scan_id)
            assert scan is not None and scan.status == "completed"
            db.session.remove()
    finally:
        _drop(database_url, schema, app)


def test_dependent_checks_are_never_skipped_because_of_timing(database_url: str) -> None:
    app, schema = _concurrent_app(database_url)
    try:
        start_scan_for(app)
        first = Probe("first", hold=0.02)
        second = FakeCheck("second", "host", needs=("first",))
        names = [f"h{n:02}.example.com" for n in range(40)]
        registry: dict[str, Any] = {
            "discovery": discovery(*names),
            "first": first,
            "second": second,
        }

        worker.run_worker(app, once=True, threads=8, registry=registry)

        with app.app_context():
            outcomes = db.session.execute(
                select(CheckResult.status, func.count())
                .where(CheckResult.check_key == "second")
                .group_by(CheckResult.status)
            ).all()
            assert outcomes == [("ok", 41)]  # every dependent ran after its prerequisite
            db.session.remove()
    finally:
        _drop(database_url, schema, app)


def test_two_scans_each_get_their_own_limit(database_url: str) -> None:
    app, schema = _concurrent_app(database_url)
    try:
        start_scan_for(app, "one.example.org")
        start_scan_for(app, "two.example.org")
        probe = Probe(hold=0.05)
        names_one = [f"h{n}.one.example.org" for n in range(20)]
        names_two = [f"h{n}.two.example.org" for n in range(20)]

        class PerDomainDiscovery(FakeCheck):
            def run(self, ctx: CheckContext) -> CheckOutcome:
                names = names_one if ctx.domain.startswith("one") else names_two
                return CheckOutcome("ok", data=discovery_data(*names))

        registry: dict[str, Any] = {
            "discovery": PerDomainDiscovery("discovery", "domain"),
            "probe": probe,
        }
        worker.run_worker(app, once=True, threads=8, registry=registry)

        assert 4 < probe.max_active <= 8  # more than one scan's limit, never more than the threads
        with app.app_context():
            states = db.session.scalars(select(Scan.status)).all()
            assert states == ["completed", "completed"]
            db.session.remove()
    finally:
        _drop(database_url, schema, app)


def test_the_worker_command_accepts_a_thread_count(cli_runner: Any) -> None:
    result = cli_runner.invoke(args=["worker", "--once", "--threads", "2"])
    assert result.exit_code == 0, result.output
    assert "Processed 0 task(s)." in result.output
    assert cli_runner.invoke(args=["worker", "--once", "--threads", "0"]).exit_code == 2
