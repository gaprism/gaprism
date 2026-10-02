"""Scan run lifecycle state machine, cancellation, and job coordination."""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.base import utc_now
from app.models.job import Job
from app.models.scan_run import ScanRun
from app.service.jobs.queue import cancel_job, enqueue_job


def start_run(
    session: Session,
    assessment_id: uuid.UUID,
    requested_by: uuid.UUID,
    request_key: str,
    target_domain: str,
    scope_snapshot: dict[str, Any] | None = None,
    redacted_config: dict[str, Any] | None = None,
    profile_version: str = "1.0",
) -> ScanRun:
    """Initiate a new scan run for an assessment with initial discovery job."""
    # Check idempotency by (assessment_id, request_key)
    stmt = (
        select(ScanRun)
        .where(
            ScanRun.assessment_id == assessment_id,
            ScanRun.request_key == request_key,
        )
        .with_for_update()
    )
    existing_run = session.execute(stmt).scalar_one_or_none()
    if existing_run is not None:
        return existing_run

    assessment = session.execute(
        select(Assessment).where(Assessment.id == assessment_id)
    ).scalar_one_or_none()
    if assessment is None:
        raise ValueError(f"Assessment {assessment_id} not found.")

    scan_run = ScanRun(
        workspace_id=assessment.workspace_id,
        assessment_id=assessment_id,
        requested_by=requested_by,
        request_key=request_key,
        target_domain=target_domain.strip().lower(),
        status="queued",
        scope_snapshot=scope_snapshot or {"scope": target_domain},
        redacted_config=redacted_config or {},
        profile_version=profile_version,
    )
    session.add(scan_run)
    session.flush()

    # Enqueue seed discovery job
    enqueue_job(
        session=session,
        workspace_id=assessment.workspace_id,
        assessment_id=assessment_id,
        run_id=scan_run.id,
        job_type="discovery_ct",
        logical_key=f"ct:{target_domain.strip().lower()}",
        payload={"target_domain": target_domain.strip().lower()},
        priority=10,
    )
    session.flush()
    return scan_run


def cancel_run(
    session: Session,
    run_id: uuid.UUID,
    reason: str = "User requested cancellation",
) -> ScanRun:
    """Cancel a scan run and terminate all associated queued/running jobs."""
    stmt = select(ScanRun).where(ScanRun.id == run_id).with_for_update()
    scan_run = session.execute(stmt).scalar_one_or_none()
    if scan_run is None:
        raise ValueError(f"ScanRun {run_id} not found.")

    if scan_run.is_terminal():
        return scan_run

    now = utc_now()
    scan_run.status = "cancelled"
    scan_run.terminal_at = now
    scan_run.cancellation_reason = reason
    scan_run.revision += 1

    # Cancel all non-terminal child jobs
    jobs_stmt = (
        select(Job)
        .where(
            Job.run_id == run_id,
            Job.status.in_(["queued", "running", "waiting_provider"]),
        )
        .with_for_update()
    )
    jobs = list(session.execute(jobs_stmt).scalars().all())
    for job in jobs:
        cancel_job(session, job_id=job.id, reason=reason)

    session.flush()
    return scan_run


def check_and_finalize_run(
    session: Session,
    run_id: uuid.UUID,
) -> ScanRun:
    """Evaluate child job states and finalize scan run in a thread-safe locked transaction.

    Acquires row-level FOR UPDATE lock on ScanRun (JOB-03) to prevent race conditions
    when child jobs are being inserted by concurrent discovery/enrichment workers.
    """
    stmt = select(ScanRun).where(ScanRun.id == run_id).with_for_update()
    scan_run = session.execute(stmt).scalar_one_or_none()
    if scan_run is None:
        raise ValueError(f"ScanRun {run_id} not found.")

    if scan_run.is_terminal():
        return scan_run

    # Query all child jobs for this run
    jobs_stmt = select(Job).where(Job.run_id == run_id)
    all_jobs = list(session.execute(jobs_stmt).scalars().all())

    if not all_jobs:
        return scan_run

    active_jobs = [
        job for job in all_jobs if job.status in {"queued", "running", "waiting_provider"}
    ]

    now = utc_now()
    if active_jobs:
        # Run has pending work
        if scan_run.status == "queued":
            scan_run.status = "running"
            scan_run.started_at = scan_run.started_at or now
            scan_run.revision += 1
            session.flush()
        return scan_run

    # All jobs are in terminal state
    completed_count = sum(1 for job in all_jobs if job.status == "completed")
    failed_count = sum(1 for job in all_jobs if job.status == "failed")
    cancelled_count = sum(1 for job in all_jobs if job.status == "cancelled")

    if cancelled_count > 0 and completed_count == 0:
        scan_run.status = "cancelled"
    elif failed_count > 0 and completed_count == 0:
        scan_run.status = "failed"
    elif failed_count > 0 or cancelled_count > 0:
        # Some failed/cancelled but partial results were obtained
        scan_run.status = "partial"
    else:
        # All completed successfully
        scan_run.status = "completed"

    scan_run.terminal_at = now
    scan_run.revision += 1
    session.flush()
    return scan_run
