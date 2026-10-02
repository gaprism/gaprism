"""Acceptance and unit tests for durable job queue, lease claiming, and generation fencing."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import User, Workspace
from app.models.job import Job, JobAttempt
from app.models.scan_run import ScanRun
from app.service.jobs.queue import (
    cancel_job,
    claim_jobs,
    complete_job,
    enqueue_job,
    fail_job,
    heartbeat,
)


@pytest.fixture
def test_setup_entities(db_session: Session) -> tuple[Workspace, User, Assessment, ScanRun]:
    """Create basic entities required for job queue tests."""
    ws = Workspace(name="Queue Test Workspace", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(
        email="operator@example.com",
        password="hashedpassword123",
        active=True,
    )
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Queue Inc",
        scope_ascii="example.org",
        scope_display="example.org",
        created_by=user.id,
        owner_user_id=user.id,
        state="active",
    )
    db_session.add(assessment)
    db_session.flush()

    scan_run = ScanRun(
        workspace_id=ws.id,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key="run-key-1",
        target_domain="example.org",
        status="running",
    )
    db_session.add(scan_run)
    db_session.commit()

    return ws, user, assessment, scan_run


def test_enqueue_job_idempotency(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """Verify that enqueueing with identical (run_id, logical_key) is idempotent."""
    ws, _, assessment, scan_run = test_setup_entities

    job1 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="discovery_ct",
        logical_key="ct:example.org",
        payload={"domain": "example.org"},
    )
    db_session.commit()

    job2 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="discovery_ct",
        logical_key="ct:example.org",
        payload={"domain": "example.org"},
    )
    db_session.commit()

    assert job1.id == job2.id
    total_jobs = db_session.query(Job).filter_by(run_id=scan_run.id).count()
    assert total_jobs == 1


def test_claim_and_complete_job_lifecycle(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """Verify normal claim, heartbeat, and completion flow with attempt tracking."""
    ws, _, assessment, scan_run = test_setup_entities

    job = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="dns_resolve",
        logical_key="dns:api.example.org",
        payload={"host": "api.example.org"},
    )
    db_session.commit()

    # Worker 1 claims job
    claimed = claim_jobs(db_session, worker_id="worker-node-1", batch_size=10)
    db_session.commit()

    assert len(claimed) == 1
    c_job = claimed[0]
    assert c_job.id == job.id
    assert c_job.status == "running"
    assert c_job.lease_owner == "worker-node-1"
    assert c_job.generation_id == 1
    assert c_job.attempts == 1

    # Heartbeat
    hb_success = heartbeat(
        db_session,
        job_id=c_job.id,
        worker_id="worker-node-1",
        generation_id=1,
        lease_duration=timedelta(minutes=5),
    )
    db_session.commit()
    assert hb_success is True

    # Complete job
    res = complete_job(
        db_session,
        job_id=c_job.id,
        worker_id="worker-node-1",
        generation_id=1,
        result_payload={"ips": ["93.184.216.34"]},
    )
    db_session.commit()
    assert res is True

    # Verify DB state
    db_session.refresh(job)
    assert job.status == "completed"
    assert job.result_payload == {"ips": ["93.184.216.34"]}
    assert job.lease_owner is None
    assert job.lease_expires_at is None

    attempts = db_session.query(JobAttempt).filter_by(job_id=job.id).all()
    assert len(attempts) == 1
    assert attempts[0].status == "succeeded"
    assert attempts[0].generation_id == 1
    assert attempts[0].finished_at is not None


def test_job01_worker_crash_and_lease_recovery(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """JOB-01: Simulate worker crash during execution; verify lease recovery and reclamation."""
    ws, _, assessment, scan_run = test_setup_entities

    job = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="tls_probe",
        logical_key="tls:example.org:443",
        payload={"host": "example.org", "port": 443},
    )
    db_session.commit()

    # Worker 1 claims job with a short lease (e.g. expired in the past)
    now = datetime.now(UTC)
    job.status = "running"
    job.lease_owner = "crashed-worker-1"
    job.lease_expires_at = now - timedelta(seconds=10)
    job.generation_id = 1
    job.attempts = 1
    db_session.commit()

    # Worker 2 attempts to claim jobs; should recover the expired lease
    reclaimed = claim_jobs(db_session, worker_id="healthy-worker-2", batch_size=10)
    db_session.commit()

    assert len(reclaimed) == 1
    rec_job = reclaimed[0]
    assert rec_job.id == job.id
    assert rec_job.status == "running"
    assert rec_job.lease_owner == "healthy-worker-2"
    assert rec_job.generation_id == 2  # Incremented generation
    assert rec_job.attempts == 2

    # Worker 2 successfully completes
    res = complete_job(
        db_session,
        job_id=rec_job.id,
        worker_id="healthy-worker-2",
        generation_id=2,
        result_payload={"tls_version": "TLSv1.3"},
    )
    db_session.commit()
    assert res is True

    db_session.refresh(job)
    assert job.status == "completed"


def test_job02_generation_fencing_rejects_stale_worker(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """JOB-02: Verify that slow worker cannot commit after lease expiration & reassignment."""
    ws, _, assessment, scan_run = test_setup_entities

    job = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="enrich_shodan",
        logical_key="shodan:93.184.216.34",
        payload={"ip": "93.184.216.34"},
    )
    db_session.commit()

    # Worker 1 claims job (gen 1)
    worker1_jobs = claim_jobs(db_session, worker_id="slow-worker-1", batch_size=1)
    db_session.commit()
    w1_job = worker1_jobs[0]
    assert w1_job.generation_id == 1

    # Worker 1 hangs; lease expires in DB
    now = datetime.now(UTC)
    w1_job.lease_expires_at = now - timedelta(seconds=5)
    db_session.commit()

    # Worker 2 reclaims job (gen 2)
    worker2_jobs = claim_jobs(db_session, worker_id="fast-worker-2", batch_size=1)
    db_session.commit()
    w2_job = worker2_jobs[0]
    assert w2_job.generation_id == 2

    # Now slow worker 1 wakes up and tries to complete job with generation 1
    w1_complete_result = complete_job(
        db_session,
        job_id=w1_job.id,
        worker_id="slow-worker-1",
        generation_id=1,
        result_payload={"stale": "data"},
    )
    db_session.commit()
    # Must be rejected due to generation fencing
    assert w1_complete_result is False

    # Worker 2 completes with valid generation 2
    w2_complete_result = complete_job(
        db_session,
        job_id=w2_job.id,
        worker_id="fast-worker-2",
        generation_id=2,
        result_payload={"valid": "data"},
    )
    db_session.commit()
    assert w2_complete_result is True

    db_session.refresh(job)
    assert job.status == "completed"
    assert job.result_payload == {"valid": "data"}


def test_fail_job_retry_and_exhaustion(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """Verify job retry scheduling on transient failure and terminal status on exhaustion."""
    ws, _, assessment, scan_run = test_setup_entities

    job = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="webrisk",
        logical_key="webrisk:example.org",
        payload={"url": "https://example.org"},
        max_attempts=2,
    )
    db_session.commit()

    # Attempt 1
    claimed = claim_jobs(db_session, worker_id="worker-1", batch_size=1)
    db_session.commit()
    c_job = claimed[0]

    # Fails with retry
    fail_res = fail_job(
        db_session,
        job_id=c_job.id,
        worker_id="worker-1",
        generation_id=1,
        error_message="HTTP 503 Provider Unavailable",
        retry_delay=timedelta(seconds=0),
    )
    db_session.commit()
    assert fail_res is True

    db_session.refresh(job)
    assert job.status == "queued"
    assert job.attempts == 1

    # Attempt 2 (exhausts max_attempts=2)
    claimed2 = claim_jobs(db_session, worker_id="worker-1", batch_size=1)
    db_session.commit()
    assert len(claimed2) == 1

    fail_res2 = fail_job(
        db_session,
        job_id=claimed2[0].id,
        worker_id="worker-1",
        generation_id=2,
        error_message="HTTP 503 Provider Unavailable again",
    )
    db_session.commit()
    assert fail_res2 is True

    db_session.refresh(job)
    assert job.status == "failed"
    assert job.last_error == "HTTP 503 Provider Unavailable again"


def test_cancel_job(
    db_session: Session,
    test_setup_entities: tuple[Workspace, User, Assessment, ScanRun],
) -> None:
    """Verify cancelling queued and running jobs."""
    ws, _, assessment, scan_run = test_setup_entities

    job1 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="dns_resolve",
        logical_key="dns:1",
        payload={},
    )
    job2 = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="dns_resolve",
        logical_key="dns:2",
        payload={},
    )
    db_session.commit()

    # Cancel queued job1
    assert cancel_job(db_session, job_id=job1.id, reason="User cancelled scan") is True
    db_session.commit()
    db_session.refresh(job1)
    assert job1.status == "cancelled"

    # Claim job2 then request cancel
    claimed = claim_jobs(db_session, worker_id="worker-1", batch_size=1)
    db_session.commit()
    assert len(claimed) == 1

    assert cancel_job(db_session, job_id=job2.id, reason="Emergency abort") is True
    db_session.commit()
    db_session.refresh(job2)
    assert job2.cancel_requested is True
