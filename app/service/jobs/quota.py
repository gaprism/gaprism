"""Quota ledger and rate-limiting service for third-party provider calls."""

import uuid
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.base import utc_now
from app.models.job import Job
from app.models.quota import ProviderQuota, QuotaReservation

ProviderType = Literal["ct", "shodan", "webrisk", "geoip"]
PeriodType = Literal["minute", "hour", "day", "month"]


def _calculate_next_reset(period: str, from_time: datetime) -> datetime:
    """Calculate the next reset timestamp given a period window."""
    if period == "minute":
        return from_time + timedelta(minutes=1)
    elif period == "hour":
        return from_time + timedelta(hours=1)
    elif period == "day":
        return from_time + timedelta(days=1)
    elif period == "month":
        # 30-day default window for monthly accounting
        return from_time + timedelta(days=30)
    return from_time + timedelta(hours=1)


def init_provider_quota(
    session: Session,
    workspace_id: uuid.UUID,
    provider: ProviderType,
    period: PeriodType,
    limit_amount: int,
) -> ProviderQuota:
    """Initialize or update provider quota limits for a workspace."""
    stmt = (
        select(ProviderQuota)
        .where(
            ProviderQuota.workspace_id == workspace_id,
            ProviderQuota.provider == provider,
            ProviderQuota.period == period,
        )
        .with_for_update()
    )
    quota = session.execute(stmt).scalar_one_or_none()
    now = utc_now()

    if quota is None:
        quota = ProviderQuota(
            workspace_id=workspace_id,
            provider=provider,
            period=period,
            limit_amount=limit_amount,
            used_amount=0,
            reset_at=_calculate_next_reset(period, now),
        )
        session.add(quota)
    else:
        quota.limit_amount = limit_amount
        if quota.reset_at <= now:
            quota.used_amount = 0
            quota.reset_at = _calculate_next_reset(period, now)

    session.flush()
    return quota


def reserve_quota(
    session: Session,
    workspace_id: uuid.UUID,
    provider: ProviderType,
    amount: int = 1,
    job_id: uuid.UUID | None = None,
    reservation_ttl: timedelta = timedelta(minutes=5),
) -> QuotaReservation | None:
    """Reserve API quota before invoking an external third-party API.

    Returns QuotaReservation on success, or None if quota is exhausted.
    """
    now = utc_now()
    stmt = (
        select(ProviderQuota)
        .where(
            ProviderQuota.workspace_id == workspace_id,
            ProviderQuota.provider == provider,
        )
        .with_for_update()
    )
    quotas = list(session.execute(stmt).scalars().all())

    if not quotas:
        # If no quota configured for this provider, assume allowed and create unmetered reservation
        reservation = QuotaReservation(
            workspace_id=workspace_id,
            job_id=job_id,
            provider=provider,
            amount=amount,
            status="reserved",
            expires_at=now + reservation_ttl,
        )
        session.add(reservation)
        session.flush()
        return reservation

    # Check all active quota periods (e.g. minute + day)
    for quota in quotas:
        # Check if reset window passed
        if quota.reset_at <= now:
            quota.used_amount = 0
            quota.reset_at = _calculate_next_reset(quota.period, now)

        if quota.used_amount + amount > quota.limit_amount:
            # Quota exhausted in this period window
            return None

    # Consume quota reservations in all configured periods
    for quota in quotas:
        quota.used_amount += amount

    reservation = QuotaReservation(
        workspace_id=workspace_id,
        job_id=job_id,
        provider=provider,
        amount=amount,
        status="reserved",
        expires_at=now + reservation_ttl,
    )
    session.add(reservation)
    session.flush()
    return reservation


def commit_quota(
    session: Session,
    reservation_id: uuid.UUID,
) -> bool:
    """Commit a reserved quota consumption after successful provider call."""
    stmt = select(QuotaReservation).where(QuotaReservation.id == reservation_id).with_for_update()
    reservation = session.execute(stmt).scalar_one_or_none()

    if reservation is None or reservation.status != "reserved":
        return False

    reservation.status = "committed"
    session.flush()
    return True


def release_quota(
    session: Session,
    reservation_id: uuid.UUID,
) -> bool:
    """Release a reserved quota back to the ledger upon provider call failure/cancellation."""
    stmt = select(QuotaReservation).where(QuotaReservation.id == reservation_id).with_for_update()
    reservation = session.execute(stmt).scalar_one_or_none()

    if reservation is None or reservation.status != "reserved":
        return False

    # Refund used quota
    quota_stmt = (
        select(ProviderQuota)
        .where(
            ProviderQuota.workspace_id == reservation.workspace_id,
            ProviderQuota.provider == reservation.provider,
        )
        .with_for_update()
    )
    quotas = list(session.execute(quota_stmt).scalars().all())
    for quota in quotas:
        quota.used_amount = max(0, quota.used_amount - reservation.amount)

    reservation.status = "released"
    session.flush()
    return True


def handle_quota_exhaustion(
    session: Session,
    job_id: uuid.UUID,
    provider: ProviderType,
    retry_delay: timedelta = timedelta(minutes=1),
) -> bool:
    """Transition a job to waiting_provider state due to provider rate limit/quota exhaustion."""
    stmt = select(Job).where(Job.id == job_id).with_for_update()
    job = session.execute(stmt).scalar_one_or_none()

    if job is None or job.is_terminal():
        return False

    now = utc_now()
    job.status = "waiting_provider"
    job.available_at = now + retry_delay
    job.lease_owner = None
    job.lease_expires_at = None
    job.last_error = f"Quota exhausted for provider '{provider}'; waiting for quota window reset."
    session.flush()
    return True
