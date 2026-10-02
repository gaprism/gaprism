"""Durable background job queue engine with lease claiming and generation fencing."""

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.base import utc_now
from app.models.job import Job, JobAttempt


class GenerationFencingError(Exception):
    """Raised when a worker attempts an operation with a stale generation_id or lost lease."""

    pass


def enqueue_job(
    session: Session,
    workspace_id: uuid.UUID,
    assessment_id: uuid.UUID,
    job_type: str,
    logical_key: str,
    payload: dict[str, Any],
    run_id: uuid.UUID | None = None,
    priority: int = 100,
    max_attempts: int = 3,
    available_at: datetime | None = None,
) -> Job:
    """Enqueue a job idempotently by logical_key within run scope."""
    # Check if job with (run_id, logical_key) already exists
    stmt = select(Job).where(Job.run_id == run_id, Job.logical_key == logical_key)
    existing_job = session.execute(stmt).scalar_one_or_none()
    if existing_job is not None:
        return existing_job

    job = Job(
        workspace_id=workspace_id,
        assessment_id=assessment_id,
        run_id=run_id,
        job_type=job_type,
        logical_key=logical_key,
        payload=payload,
        priority=priority,
        max_attempts=max_attempts,
        status="queued",
        available_at=available_at or utc_now(),
    )
    session.add(job)
    session.flush()
    return job


def claim_jobs(
    session: Session,
    worker_id: str,
    batch_size: int = 1,
    lease_duration: timedelta = timedelta(seconds=60),
    worker_host: str | None = None,
) -> list[Job]:
    """Claim a batch of ready jobs using PostgreSQL FOR UPDATE SKIP LOCKED.

    Claims jobs in 'queued' status that are available, or 'running' jobs whose lease
    has expired. Increments generation_id and records a JobAttempt.
    """
    now = utc_now()

    # Query claimable jobs with row-level locks skipping locked rows
    stmt = (
        select(Job)
        .where(
            or_(
                Job.status == "queued",
                and_expired_lease(now),
            ),
            Job.available_at <= now,
            Job.cancel_requested.is_(False),
        )
        .order_by(Job.priority.asc(), Job.created_at.asc())
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )

    jobs = list(session.execute(stmt).scalars().all())
    claimed_jobs: list[Job] = []

    for job in jobs:
        job.status = "running"
        job.lease_owner = worker_id
        job.lease_expires_at = now + lease_duration
        job.heartbeat_at = now
        job.generation_id += 1
        job.attempts += 1

        attempt = JobAttempt(
            job_id=job.id,
            generation_id=job.generation_id,
            started_at=now,
            status="running",
            worker_host=worker_host,
        )
        session.add(attempt)
        claimed_jobs.append(job)

    session.flush()
    return claimed_jobs


def and_expired_lease(now: datetime) -> Any:
    """Helper clause for finding jobs with expired leases."""
    return and_(Job.status == "running", Job.lease_expires_at < now)


def heartbeat(
    session: Session,
    job_id: uuid.UUID,
    worker_id: str,
    generation_id: int,
    lease_duration: timedelta = timedelta(seconds=60),
) -> bool:
    """Renew the lease on a running job if generation_id and worker match."""
    now = utc_now()
    stmt = select(Job).where(Job.id == job_id).with_for_update()
    job = session.execute(stmt).scalar_one_or_none()

    if job is None:
        return False

    if (
        job.lease_owner != worker_id
        or job.generation_id != generation_id
        or job.status != "running"
    ):
        return False

    job.lease_expires_at = now + lease_duration
    job.heartbeat_at = now
    session.flush()
    return True


def complete_job(
    session: Session,
    job_id: uuid.UUID,
    worker_id: str,
    generation_id: int,
    result_payload: dict[str, Any] | None = None,
) -> bool:
    """Complete a running job if the worker holds the valid lease and generation."""
    now = utc_now()
    stmt = select(Job).where(Job.id == job_id).with_for_update()
    job = session.execute(stmt).scalar_one_or_none()

    if job is None:
        return False

    # Generation fencing verification (JOB-02)
    if (
        job.lease_owner != worker_id
        or job.generation_id != generation_id
        or job.status != "running"
    ):
        return False

    job.status = "completed"
    job.result_payload = result_payload
    job.lease_owner = None
    job.lease_expires_at = None

    # Update corresponding JobAttempt
    attempt_stmt = (
        select(JobAttempt)
        .where(
            JobAttempt.job_id == job_id,
            JobAttempt.generation_id == generation_id,
        )
        .order_by(JobAttempt.started_at.desc())
    )
    attempt = session.execute(attempt_stmt).scalar_one_or_none()
    if attempt is not None:
        attempt.status = "succeeded"
        attempt.finished_at = now

    session.flush()
    return True


def fail_job(
    session: Session,
    job_id: uuid.UUID,
    worker_id: str,
    generation_id: int,
    error_message: str,
    retry_delay: timedelta = timedelta(seconds=10),
) -> bool:
    """Record a failure for a job and reschedule or mark failed based on max_attempts."""
    now = utc_now()
    stmt = select(Job).where(Job.id == job_id).with_for_update()
    job = session.execute(stmt).scalar_one_or_none()

    if job is None:
        return False

    # Generation fencing verification
    if (
        job.lease_owner != worker_id
        or job.generation_id != generation_id
        or job.status != "running"
    ):
        return False

    job.last_error = error_message

    # Update attempt
    attempt_stmt = (
        select(JobAttempt)
        .where(
            JobAttempt.job_id == job_id,
            JobAttempt.generation_id == generation_id,
        )
        .order_by(JobAttempt.started_at.desc())
    )
    attempt = session.execute(attempt_stmt).scalar_one_or_none()
    if attempt is not None:
        attempt.status = "failed"
        attempt.error_message = error_message
        attempt.finished_at = now

    if job.attempts < job.max_attempts and not job.cancel_requested:
        # Re-queue for next attempt after retry_delay
        job.status = "queued"
        job.available_at = now + retry_delay
        job.lease_owner = None
        job.lease_expires_at = None
    else:
        # Exhausted attempts or cancellation
        job.status = "failed"
        job.lease_owner = None
        job.lease_expires_at = None

    session.flush()
    return True


def cancel_job(
    session: Session,
    job_id: uuid.UUID,
    reason: str | None = None,
) -> bool:
    """Request cancellation for a job."""
    stmt = select(Job).where(Job.id == job_id).with_for_update()
    job = session.execute(stmt).scalar_one_or_none()

    if job is None:
        return False

    if job.is_terminal():
        return False

    if job.status == "queued":
        job.status = "cancelled"
        job.last_error = reason
    elif job.status == "running":
        job.cancel_requested = True
        job.last_error = reason

    session.flush()
    return True
