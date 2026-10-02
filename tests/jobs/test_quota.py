"""Unit and integration tests for third-party provider quota accounting and rate limits."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import User, Workspace
from app.models.scan_run import ScanRun
from app.service.jobs.queue import enqueue_job
from app.service.jobs.quota import (
    commit_quota,
    handle_quota_exhaustion,
    init_provider_quota,
    release_quota,
    reserve_quota,
)


def test_init_and_reserve_quota_success(db_session: Session) -> None:
    """Verify that provider quota is correctly initialized and reserved within limits."""
    ws = Workspace(name="Quota WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    # Initialize quota: 100 requests per day for Shodan
    quota = init_provider_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="shodan",
        period="day",
        limit_amount=100,
    )
    db_session.commit()

    assert quota.limit_amount == 100
    assert quota.used_amount == 0
    assert quota.remaining() == 100

    # Reserve 5 credits
    res = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="shodan",
        amount=5,
    )
    db_session.commit()

    assert res is not None
    assert res.status == "reserved"
    assert res.amount == 5

    db_session.refresh(quota)
    assert quota.used_amount == 5
    assert quota.remaining() == 95


def test_quota_exhaustion_blocks_further_reservations(db_session: Session) -> None:
    """Verify that exceeding provider quota limit returns None."""
    ws = Workspace(name="Quota Exhaustion WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    # Quota limit of 2 requests
    init_provider_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="webrisk",
        period="minute",
        limit_amount=2,
    )
    db_session.commit()

    # Reserve 2 requests (exhausts quota)
    res1 = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="webrisk",
        amount=2,
    )
    db_session.commit()
    assert res1 is not None

    # Third reservation should fail (exhausted)
    res2 = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="webrisk",
        amount=1,
    )
    db_session.commit()
    assert res2 is None


def test_commit_and_release_quota_refunds_ledger(db_session: Session) -> None:
    """Verify that commit retains used quota while release refunds the ledger."""
    ws = Workspace(name="Quota Release WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    quota = init_provider_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="ct",
        period="hour",
        limit_amount=50,
    )
    db_session.commit()

    # Reserve 10 credits
    res = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="ct",
        amount=10,
    )
    db_session.commit()
    assert res is not None

    db_session.refresh(quota)
    assert quota.used_amount == 10

    # Release (e.g. on call failure)
    released = release_quota(db_session, reservation_id=res.id)
    db_session.commit()
    assert released is True

    db_session.refresh(res)
    assert res.status == "released"

    db_session.refresh(quota)
    assert quota.used_amount == 0
    assert quota.remaining() == 50

    # Reserve again and commit
    res2 = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="ct",
        amount=10,
    )
    db_session.commit()
    assert res2 is not None

    committed = commit_quota(db_session, reservation_id=res2.id)
    db_session.commit()
    assert committed is True

    db_session.refresh(res2)
    assert res2.status == "committed"

    db_session.refresh(quota)
    assert quota.used_amount == 10


def test_handle_quota_exhaustion_transitions_job(db_session: Session) -> None:
    """Verify handle_quota_exhaustion updates job to waiting_provider state."""
    ws = Workspace(name="Quota Job WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    user = User(
        email="quota-test@example.com",
        password="hashedpassword123",
        active=True,
    )
    db_session.add(user)
    db_session.flush()

    assessment = Assessment(
        workspace_id=ws.id,
        supplier_label="Vendor Quota",
        scope_ascii="example.com",
        scope_display="example.com",
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
        request_key="run-quota-1",
        target_domain="example.com",
        status="running",
    )
    db_session.add(scan_run)
    db_session.flush()

    job = enqueue_job(
        session=db_session,
        workspace_id=ws.id,
        assessment_id=assessment.id,
        run_id=scan_run.id,
        job_type="enrich_shodan",
        logical_key="shodan:1.1.1.1",
        payload={"ip": "1.1.1.1"},
    )
    db_session.commit()

    # Handle exhaustion
    res = handle_quota_exhaustion(
        session=db_session,
        job_id=job.id,
        provider="shodan",
        retry_delay=timedelta(minutes=2),
    )
    db_session.commit()
    assert res is True

    db_session.refresh(job)
    assert job.status == "waiting_provider"
    assert job.lease_owner is None
    assert job.available_at > datetime.now(UTC)
    assert "Quota exhausted for provider 'shodan'" in (job.last_error or "")


def test_quota_reset_after_period_window(db_session: Session) -> None:
    """Verify that used quota resets once the reset_at timestamp has elapsed."""
    ws = Workspace(name="Quota Window WS", enabled=True)
    db_session.add(ws)
    db_session.flush()

    quota = init_provider_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="geoip",
        period="minute",
        limit_amount=5,
    )
    # Simulate that quota was fully consumed in the past window
    quota.used_amount = 5
    quota.reset_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    # New reservation should detect window elapsed, reset used_amount, and succeed
    res = reserve_quota(
        session=db_session,
        workspace_id=ws.id,
        provider="geoip",
        amount=3,
    )
    db_session.commit()
    assert res is not None

    db_session.refresh(quota)
    assert quota.used_amount == 3
    assert quota.remaining() == 2
