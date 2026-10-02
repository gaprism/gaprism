"""ProviderQuota and QuotaReservation models for rate limiting and API accounting."""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.auth import Workspace
from app.models.base import BaseUUIDModel, TimestampMixin
from app.models.job import Job


class ProviderQuota(BaseUUIDModel, TimestampMixin):
    """Ledger table tracking credit limits, consumption, and reset windows per provider."""

    __tablename__ = "provider_quota"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    period: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    limit_amount: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    used_amount: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    reset_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    workspace: Mapped[Workspace] = relationship("Workspace")

    __table_args__ = (
        UniqueConstraint("workspace_id", "provider", "period", name="uq_provider_quota_window"),
        CheckConstraint(
            "provider IN ('ct', 'shodan', 'webrisk', 'geoip')",
            name="ck_provider_quota_provider",
        ),
        CheckConstraint(
            "period IN ('minute', 'hour', 'day', 'month')",
            name="ck_provider_quota_period",
        ),
        CheckConstraint("limit_amount >= 0", name="ck_provider_quota_limit_non_negative"),
        CheckConstraint("used_amount >= 0", name="ck_provider_quota_used_non_negative"),
    )

    def remaining(self) -> int:
        """Calculate remaining quota available in this period."""
        return max(0, self.limit_amount - self.used_amount)

    def __repr__(self) -> str:
        return (
            f"<ProviderQuota {self.provider} ({self.period}) "
            f"used={self.used_amount}/{self.limit_amount} "
            f"resets_at={self.reset_at}>"
        )


class QuotaReservation(BaseUUIDModel, TimestampMixin):
    """Pre-call reservation of provider quota attached to a background job."""

    __tablename__ = "quota_reservation"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("job.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    amount: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="reserved",
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    workspace: Mapped[Workspace] = relationship("Workspace")
    job: Mapped[Job | None] = relationship("Job")

    __table_args__ = (
        CheckConstraint(
            "provider IN ('ct', 'shodan', 'webrisk', 'geoip')",
            name="ck_quota_reservation_provider",
        ),
        CheckConstraint(
            "status IN ('reserved', 'committed', 'released')",
            name="ck_quota_reservation_status",
        ),
        CheckConstraint("amount > 0", name="ck_quota_reservation_amount_positive"),
    )

    def __repr__(self) -> str:
        return (
            f"<QuotaReservation {self.id} provider={self.provider} amount={self.amount} "
            f"status={self.status}>"
        )
