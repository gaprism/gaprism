"""The scan engine: claims queued check rows, runs the checks, stores outcomes.

``check_result`` rows in status ``queued`` are the work queue. Workers claim them with
``FOR UPDATE SKIP LOCKED``, run the check *outside* any database transaction, and store the
outcome in a short transaction. A crashed worker leaves a ``running`` row behind; it is queued
again after ``STALE_LOCK`` and, if it keeps failing, ends as an error. Unique keys on
``check_result`` make repeats harmless, and a result from a worker that lost its lock is
discarded.

``run_worker`` runs several of these loops in threads. A task waits until the checks it needs
for the same host are finished, and at most ``PER_TARGET_CONCURRENCY`` tasks of one scan run at
the same time (per process), so a large scan never floods the domain it is looking at.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

import httpx
from flask import Flask
from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult, Result
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY, REGISTRY, Check, CheckContext, CheckOutcome
from app.extensions import db
from app.models import Assessment, CheckResult, Host, Scan
from app.models.base import utc_now
from app.service import scans as scan_service

log = logging.getLogger(__name__)

STALE_LOCK = timedelta(minutes=10)
MAX_ATTEMPTS = 3
CLAIM_BATCH = (
    100  # candidates looked at per claim; tasks waiting for a prerequisite are passed over
)
HOUSEKEEPING_INTERVAL = 30.0  # seconds between one worker's sweeps for stale locks
OPEN_STATUSES = ("queued", "running")


def _rowcount(result: Result[Any]) -> int:
    """Rows affected by an UPDATE (at runtime the result is a ``CursorResult``)."""
    return int(cast("CursorResult[Any]", result).rowcount or 0)


def requeue_stale(session: Session, now: datetime) -> int:
    """Re-queue tasks whose worker disappeared; tasks that failed too often end as errors."""
    cutoff = now - STALE_LOCK
    exhausted = _rowcount(
        session.execute(
            update(CheckResult)
            .where(
                CheckResult.status == "running",
                CheckResult.locked_at < cutoff,
                CheckResult.attempts >= MAX_ATTEMPTS,
            )
            .values(
                status="error",
                reason_code="max_attempts_exceeded",
                locked_by=None,
                locked_at=None,
                collected_at=now,
            )
        )
    )
    requeued = _rowcount(
        session.execute(
            update(CheckResult)
            .where(CheckResult.status == "running", CheckResult.locked_at < cutoff)
            .values(status="queued", locked_by=None, locked_at=None)
        )
    )
    if exhausted:
        # Giving up on a task may be what finishes its scan.
        for scan_id in session.scalars(
            select(CheckResult.scan_id)
            .where(
                CheckResult.reason_code == "max_attempts_exceeded", CheckResult.collected_at == now
            )
            .distinct()
        ):
            scan_service.finalize_scan_if_done(session, scan_id)
    session.commit()
    return exhausted + requeued


def _prerequisites_pending(
    session: Session, scan_id: uuid.UUID, host_id: uuid.UUID | None, needs: Collection[str]
) -> bool:
    """True while a check this one needs is still queued or running for the same host."""
    pending = session.scalar(
        select(func.count())
        .select_from(CheckResult)
        .where(
            CheckResult.scan_id == scan_id,
            CheckResult.host_id == host_id
            if host_id is not None
            else CheckResult.host_id.is_(None),
            CheckResult.check_key.in_(list(needs)),
            CheckResult.status.in_(OPEN_STATUSES),
        )
    )
    return bool(pending)


def claim_next(
    session: Session,
    worker_id: str,
    now: datetime,
    *,
    registry: Mapping[str, Check] | None = None,
    exclude_scans: Collection[uuid.UUID] = (),
) -> CheckResult | None:
    """Claim the oldest queued task that may run now, or return ``None``.

    A task waits while a check it needs for the same host is still open, and tasks of
    ``exclude_scans`` (scans at their concurrency limit) are passed over. Only the claimed row is
    locked; if another worker takes a candidate first, the next one is tried.
    """
    registry = REGISTRY if registry is None else registry
    for _ in range(3):  # a second round only happens when rivals took every candidate
        query = select(
            CheckResult.id, CheckResult.scan_id, CheckResult.host_id, CheckResult.check_key
        ).where(CheckResult.status == "queued")
        if exclude_scans:
            query = query.where(CheckResult.scan_id.not_in(list(exclude_scans)))
        candidates = session.execute(
            query.order_by(CheckResult.created_at).limit(CLAIM_BATCH)
        ).all()
        lost_a_race = False
        for row_id, scan_id, host_id, check_key in candidates:
            check = registry.get(check_key)
            if (
                check is not None
                and check.needs
                and _prerequisites_pending(session, scan_id, host_id, check.needs)
            ):
                continue
            task = session.scalars(
                select(CheckResult)
                .where(CheckResult.id == row_id, CheckResult.status == "queued")
                .with_for_update(skip_locked=True)
            ).first()
            if task is None:
                lost_a_race = True
                continue
            task.status = "running"
            task.locked_by = worker_id
            task.locked_at = now
            task.attempts += 1
            session.commit()
            return task
        if not lost_a_race:
            break
    session.rollback()
    return None


def _previous_outcomes(
    session: Session, task: CheckResult, check: Check
) -> dict[str, CheckOutcome]:
    """Outcomes of the checks this one needs, for the same host (or the domain)."""
    if not check.needs:
        return {}
    rows = session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == task.scan_id,
            CheckResult.host_id == task.host_id
            if task.host_id is not None
            else CheckResult.host_id.is_(None),
            CheckResult.check_key.in_(check.needs),
        )
    )
    return {
        row.check_key: CheckOutcome(row.status, row.reason_code, dict(row.data), row.source)  # type: ignore[arg-type]
        for row in rows
    }


def _run_check(check: Check, ctx: CheckContext) -> CheckOutcome:
    """Run a check; an unexpected exception becomes an error outcome (logged, not exposed)."""
    try:
        return check.run(ctx)
    except Exception:
        log.exception("check %s crashed for %s", check.key, ctx.hostname or ctx.domain)
        return CheckOutcome("error", "internal_error")


def execute_task(
    session: Session,
    task: CheckResult,
    worker_id: str,
    *,
    config: Mapping[str, Any],
    http: httpx.Client,
    registry: Mapping[str, Check] | None = None,
) -> bool:
    """Run a claimed task and store its outcome. Returns False if the result was discarded."""
    registry = REGISTRY if registry is None else registry
    scan = session.get(Scan, task.scan_id)
    assessment = session.get(Assessment, scan.assessment_id) if scan else None
    host = session.get(Host, task.host_id) if task.host_id else None
    check = registry.get(task.check_key)
    if scan is None or assessment is None:
        outcome = CheckOutcome("error", "scan_missing")
    elif check is None:
        outcome = CheckOutcome("error", "unknown_check")
    elif scan.status == "cancelled":
        outcome = CheckOutcome("skipped", "scan_cancelled")
    else:
        if scan.status == "queued":
            scan.status = "running"
            scan.started_at = utc_now()
        previous = _previous_outcomes(session, task, check)
        unmet = [key for key in check.needs if key not in previous or previous[key].status != "ok"]
        if unmet:
            outcome = CheckOutcome("skipped", "needs:" + ",".join(unmet))
        else:
            ctx = CheckContext(
                domain=assessment.domain,
                hostname=host.hostname if host else None,
                config=config,
                http=http,
                previous=previous,
            )
            session.commit()  # release the connection while the check talks to the network
            started = time.monotonic()
            outcome = _run_check(check, ctx)
            return _store_outcome(
                session,
                task,
                worker_id,
                outcome,
                int((time.monotonic() - started) * 1000),
                registry,
            )
    return _store_outcome(session, task, worker_id, outcome, 0, registry)


def _store_outcome(
    session: Session,
    task: CheckResult,
    worker_id: str,
    outcome: CheckOutcome,
    duration_ms: int,
    registry: Mapping[str, Check],
) -> bool:
    """Persist an outcome if this worker still holds the task; expand discovery; finalise."""
    row = session.scalar(select(CheckResult).where(CheckResult.id == task.id).with_for_update())
    if row is None or row.status != "running" or row.locked_by != worker_id:
        log.warning("discarding the result of task %s: its lock was lost", task.id)
        session.rollback()
        return False
    row.status = outcome.status
    row.reason_code = outcome.reason_code
    row.data = outcome.data
    row.source = outcome.source
    row.collected_at = utc_now()
    row.duration_ms = duration_ms
    row.locked_by = None
    row.locked_at = None
    session.flush()
    scan = session.get(Scan, row.scan_id)
    # A scan cancelled while discovery ran keeps the discovery result but gets no host tasks.
    if scan is not None and row.check_key == DISCOVERY_KEY and scan.status != "cancelled":
        scan_service.apply_discovery(session, scan, row, registry)
    scan_service.finalize_scan_if_done(session, row.scan_id)
    session.commit()
    return True


def process_one(
    session: Session,
    worker_id: str,
    *,
    config: Mapping[str, Any],
    http: httpx.Client,
    registry: Mapping[str, Check] | None = None,
) -> bool:
    """Claim and run one task. Returns whether there was any work."""
    now = utc_now()
    requeue_stale(session, now)
    task = claim_next(session, worker_id, now, registry=registry)
    if task is None:
        return False
    execute_task(session, task, worker_id, config=config, http=http, registry=registry)
    return True


# --------------------------------------------------------------------------- the thread pool


class TargetLimiter:
    """At most ``limit`` tasks of one scan run at the same time in this process."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("The per-target limit must be at least 1.")
        self.limit = limit
        self._running: Counter[uuid.UUID] = Counter()
        self._lock = threading.Lock()

    def full(self) -> frozenset[uuid.UUID]:
        """The scans that cannot take another task right now."""
        with self._lock:
            return frozenset(scan for scan, count in self._running.items() if count >= self.limit)

    def enter(self, scan_id: uuid.UUID) -> None:
        with self._lock:
            self._running[scan_id] += 1

    def leave(self, scan_id: uuid.UUID) -> None:
        with self._lock:
            self._running[scan_id] -= 1
            if self._running[scan_id] <= 0:
                del self._running[scan_id]

    @property
    def active(self) -> int:
        """How many tasks run in this process right now."""
        with self._lock:
            return sum(self._running.values())


class _Interval:
    """``due()`` is true at most once per ``seconds``, whichever thread asks."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._next = 0.0
        self._lock = threading.Lock()

    def due(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                return False
            self._next = now + self.seconds
            return True


class _Wakeup:
    """Lets idle threads know that a finished task may have queued or unblocked work.

    A thread reads the generation *before* it looks for work and waits for it to change, so a
    notification that arrives between "found nothing" and "start waiting" is not lost.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._generation = 0

    def mark(self) -> int:
        with self._condition:
            return self._generation

    def notify(self) -> None:
        with self._condition:
            self._generation += 1
            self._condition.notify_all()

    def wait(self, seen: int, timeout: float) -> None:
        with self._condition:
            self._condition.wait_for(lambda: self._generation != seen, timeout)


@dataclass(frozen=True)
class _Shared:
    """What all threads of one worker process share."""

    limiter: TargetLimiter
    claim_lock: threading.Lock  # makes "which scans are full? -> claim -> count it" one step
    sweep: _Interval
    wakeup: _Wakeup
    stop: threading.Event


def _claim(
    session: Session, name: str, shared: _Shared, registry: Mapping[str, Check] | None
) -> CheckResult | None:
    with shared.claim_lock:
        if shared.sweep.due():
            requeue_stale(session, utc_now())
        task = claim_next(
            session,
            name,
            utc_now(),
            registry=registry,
            exclude_scans=shared.limiter.full(),
        )
        if task is not None:
            shared.limiter.enter(task.scan_id)
        return task


def _work(
    app: Flask,
    name: str,
    http: httpx.Client,
    shared: _Shared,
    registry: Mapping[str, Check] | None,
    once: bool,
    poll_interval: float,
) -> int:
    """One worker thread: claim, run, store, until stopped (or, with ``once``, all is done)."""
    processed = 0
    failures = 0
    with app.app_context():
        session = db.session()
        while not shared.stop.is_set():
            seen = shared.wakeup.mark()
            try:
                task = _claim(session, name, shared, registry)
                if task is None and once and shared.limiter.active == 0:
                    # Nothing runs anywhere in this process; a task that just finished may have
                    # queued more work (discovery does), so look once more before giving up.
                    task = _claim(session, name, shared, registry)
                    if task is None:
                        break
                if task is None:
                    shared.wakeup.wait(seen, poll_interval)
                    continue
                try:
                    execute_task(
                        session, task, name, config=app.config, http=http, registry=registry
                    )
                finally:
                    shared.limiter.leave(task.scan_id)
                    shared.wakeup.notify()  # it may have queued work or unblocked a dependent
                processed += 1
                failures = 0
            except Exception:
                log.exception("worker %s: a round failed", name)
                db.session.remove()  # drop a possibly broken connection
                session = db.session()
                failures += 1
                if once and failures >= 3:
                    raise
                shared.wakeup.wait(seen, poll_interval)
        db.session.remove()
    return processed


def run_worker(
    app: Flask,
    *,
    worker_id: str | None = None,
    once: bool = False,
    poll_interval: float = 2.0,
    stop: threading.Event | None = None,
    threads: int | None = None,
    registry: Mapping[str, Check] | None = None,
) -> int:
    """Process queued tasks with several threads until ``stop`` is set (or, with ``once``, until
    nothing is left to do). Returns how many tasks this process ran."""
    count = int(threads if threads is not None else app.config["WORKER_THREADS"])
    if count < 1:
        raise ValueError("A worker needs at least one thread.")
    base = (worker_id or f"{socket.gethostname()}:{os.getpid()}")[:56]  # locked_by is 64 wide
    shared = _Shared(
        limiter=TargetLimiter(int(app.config["PER_TARGET_CONCURRENCY"])),
        claim_lock=threading.Lock(),
        sweep=_Interval(HOUSEKEEPING_INTERVAL),
        wakeup=_Wakeup(),
        stop=stop or threading.Event(),
    )
    processed = [0] * count
    errors: list[BaseException] = []

    def run(index: int, http: httpx.Client) -> None:
        try:
            processed[index] = _work(
                app, f"{base}#{index}", http, shared, registry, once, poll_interval
            )
        except BaseException as exc:  # reported by the main thread after the others stopped
            errors.append(exc)
            shared.stop.set()
            shared.wakeup.notify()

    with httpx.Client(
        timeout=float(app.config["PROVIDER_TIMEOUT_SECONDS"]),
        headers={"User-Agent": str(app.config["USER_AGENT"])},
        follow_redirects=False,
        trust_env=False,
    ) as http:
        pool = [
            threading.Thread(target=run, args=(index, http), name=f"worker-{index}", daemon=True)
            for index in range(count)
        ]
        for thread in pool:
            thread.start()
        try:
            while any(thread.is_alive() for thread in pool):
                for thread in pool:
                    thread.join(timeout=0.2)
        except KeyboardInterrupt:
            shared.stop.set()
            shared.wakeup.notify()
            for thread in pool:
                thread.join(timeout=10)
            raise
    if errors:
        raise errors[0]
    return sum(processed)
