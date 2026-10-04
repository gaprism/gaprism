"""The scan engine: claims queued check rows, runs the checks, stores outcomes.

``check_result`` rows in status ``queued`` are the work queue. Workers claim them with
``FOR UPDATE SKIP LOCKED``, run the check *outside* any database transaction, and store the
outcome in a short transaction. A crashed worker leaves a ``running`` row behind; it is queued
again after ``STALE_LOCK`` and, if it keeps failing, ends as an error. Unique keys on
``check_result`` make repeats harmless, and a result from a worker that lost its lock is
discarded.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, cast

import httpx
from flask import Flask
from sqlalchemy import select, update
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


def claim_next(session: Session, worker_id: str, now: datetime) -> CheckResult | None:
    """Claim the oldest queued task, or return ``None`` when the queue is empty."""
    task = session.scalars(
        select(CheckResult)
        .where(CheckResult.status == "queued")
        .order_by(CheckResult.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    ).first()
    if task is None:
        session.rollback()
        return None
    task.status = "running"
    task.locked_by = worker_id
    task.locked_at = now
    task.attempts += 1
    session.commit()
    return task


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
    if scan is not None and row.check_key == DISCOVERY_KEY:
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
    task = claim_next(session, worker_id, now)
    if task is None:
        return False
    execute_task(session, task, worker_id, config=config, http=http, registry=registry)
    return True


def run_worker(
    app: Flask,
    *,
    worker_id: str | None = None,
    once: bool = False,
    poll_interval: float = 2.0,
    stop: threading.Event | None = None,
) -> int:
    """Process queued tasks until the queue is empty (``once``) or ``stop`` is set."""
    worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
    processed = 0
    stopper = stop or threading.Event()
    with (
        app.app_context(),
        httpx.Client(
            timeout=float(app.config["PROVIDER_TIMEOUT_SECONDS"]),
            headers={"User-Agent": str(app.config["USER_AGENT"])},
            follow_redirects=False,
            trust_env=False,
        ) as http,
    ):
        while not stopper.is_set():
            if process_one(db.session(), worker_id, config=app.config, http=http):
                processed += 1
                continue
            if once:
                break
            stopper.wait(poll_interval)
    return processed
