"""Unit and concurrency tests for scan run lifecycle, cancellation, and JOB-03 race prevention."""

from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import User, Workspace
from app.models.job import Job
from app.models.scan_run import ScanRun
from app.service.assessment.run_manager import (
    cancel_run,
    check_and_finalize_run,
    start_run,
)
from app.service.jobs.queue import (
    claim_jobs,
    complete_job,
    enqueue_job,
    fail_job,
)


def test_start_run_idempotency_and_seed_job(db_session: Session) -> None:
    """Verify start_run creates run and enqueues initial seed discovery job idempotently."""
    ws = Workspace(name="Run WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(
        email="runner@example.com",
        password="hashedpassword123",
        active=True,
    )
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Run Test",
        scope_ascii="target.example.org",
        scope_display="target.example.org",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    run1 = start_run(
        session=db_session,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="unique-req-1",
        target_domain="target.example.org",
    )
    db_session.commit()

    assert run1.status == "queued"
    assert run1.target_domain == "target.example.org"

    # Verify seed discovery job exists
    jobs = db_session.query(Job).filter_by(run_id=run1.id).all()
    assert len(jobs) == 1
    assert jobs[0].job_type == "discovery_ct"
    assert jobs[0].logical_key == "ct:target.example.org"

    # Idempotent second call returns same run
    run2 = start_run(
        session=db_session,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="unique-req-1",
        target_domain="target.example.org",
    )
    db_session.commit()

    assert run1.id == run2.id
    total_runs = db_session.query(ScanRun).filter_by(assessment_id=assessment.id).count()
    assert total_runs == 1


def test_cancel_run_terminates_in_flight_jobs(db_session: Session) -> None:
    """Verify cancel_run transitions run to cancelled and cancels active/queued jobs."""
    ws = Workspace(name="Cancel WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(email="cancel@example.com", password="pwd", active=True)
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Cancel",
        scope_ascii="cancel.org",
        scope_display="cancel.org",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    run = start_run(
        session=db_session,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="cancel-req-1",
        target_domain="cancel.org",
    )
    db_session.commit()

    # Enqueue additional jobs
    job2 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=run.id,
        job_type="dns_resolve",
        logical_key="dns:cancel.org",
        payload={},
    )
    db_session.commit()

    # Claim one job so it's running
    claimed = claim_jobs(db_session, worker_id="worker-c", batch_size=1)
    db_session.commit()
    assert len(claimed) == 1

    # Cancel the run
    cancelled_run = cancel_run(
        session=db_session,
        run_id=run.id,
        reason="Security analyst stopped scan",
    )
    db_session.commit()

    assert cancelled_run.status == "cancelled"
    assert cancelled_run.terminal_at is not None
    assert cancelled_run.cancellation_reason == "Security analyst stopped scan"

    # Queued job2 should be cancelled
    db_session.refresh(job2)
    assert job2.status == "cancelled"

    # Claimed running job should have cancel_requested
    db_session.refresh(claimed[0])
    assert claimed[0].cancel_requested is True


def test_run_finalization_states(db_session: Session) -> None:
    """Verify check_and_finalize_run transitions through running, completed, partial, failed."""
    ws = Workspace(name="Finalize WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(email="final@example.com", password="pwd", active=True)
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Finalize",
        scope_ascii="finalize.org",
        scope_display="finalize.org",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    run = start_run(
        session=db_session,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="finalize-req-1",
        target_domain="finalize.org",
    )
    db_session.commit()

    # While seed job is queued: check_and_finalize sets status to running
    f_run = check_and_finalize_run(db_session, run_id=run.id)
    db_session.commit()
    assert f_run.status == "running"
    assert f_run.started_at is not None

    # Worker completes the seed job
    claimed = claim_jobs(db_session, worker_id="worker-f", batch_size=1)
    db_session.commit()
    complete_job(db_session, job_id=claimed[0].id, worker_id="worker-f", generation_id=1)
    db_session.commit()

    # Now all jobs are completed -> run completes
    f_run2 = check_and_finalize_run(db_session, run_id=run.id)
    db_session.commit()
    assert f_run2.status == "completed"
    assert f_run2.terminal_at is not None


def test_job03_finalization_race_condition_under_dynamic_insertion(
    db_session: Session,
) -> None:
    """JOB-03: Verify run finalization does not mark scan complete while child jobs in flight."""
    ws = Workspace(name="Job03 WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(email="job03@example.com", password="pwd", active=True)
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Job03",
        scope_ascii="job03.org",
        scope_display="job03.org",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    run = start_run(
        session=db_session,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="job03-req",
        target_domain="job03.org",
    )
    db_session.commit()

    # Worker 1 claims seed job (CT discovery)
    w1_jobs = claim_jobs(db_session, worker_id="ct-worker", batch_size=1)
    db_session.commit()
    ct_job = w1_jobs[0]

    # In a real workflow, before completing CT job, worker enqueues child jobs (DNS resolve)
    dns_job1 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=run.id,
        job_type="dns_resolve",
        logical_key="dns:app.job03.org",
        payload={"host": "app.job03.org"},
    )
    dns_job2 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=run.id,
        job_type="dns_resolve",
        logical_key="dns:mail.job03.org",
        payload={"host": "mail.job03.org"},
    )
    # CT job completes
    complete_job(db_session, job_id=ct_job.id, worker_id="ct-worker", generation_id=1)
    db_session.commit()

    # Finalization check must NOT mark run complete because child DNS jobs exist
    intermediate_run = check_and_finalize_run(db_session, run_id=run.id)
    db_session.commit()
    assert intermediate_run.status == "running"
    assert intermediate_run.terminal_at is None

    # Worker 2 claims and completes child jobs
    w2_jobs = claim_jobs(db_session, worker_id="dns-worker", batch_size=10)
    db_session.commit()
    assert len(w2_jobs) == 2

    # One succeeds, one fails
    complete_job(db_session, job_id=dns_job1.id, worker_id="dns-worker", generation_id=1)
    fail_job(
        db_session,
        job_id=dns_job2.id,
        worker_id="dns-worker",
        generation_id=1,
        error_message="NXDOMAIN",
    )
    # Force exhaustion on dns_job2 so it becomes terminal 'failed'
    db_session.refresh(dns_job2)
    dns_job2.status = "failed"
    db_session.commit()

    # Now all jobs are terminal -> run finalizes as 'partial' (1 succeeded, 1 failed)
    final_run = check_and_finalize_run(db_session, run_id=run.id)
    db_session.commit()
    assert final_run.status == "partial"
    assert final_run.terminal_at is not None
