"""Job and JobAttempt database models for durable background queue execution."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.assessment import Assessment
from app.models.auth import Workspace
from app.models.base import BaseUUIDModel, TimestampMixin, utc_now
from app.models.scan_run import ScanRun


class Job(BaseUUIDModel, TimestampMixin):
    """Background execution job tracked in PostgreSQL queue with lease-based claiming."""

    __tablename__ = "job"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_run.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    job_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    logical_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="queued",
        nullable=False,
        index=True,
    )
    attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        default=3,
        nullable=False,
    )
    lease_owner: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    generation_id: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    result_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    workspace: Mapped[Workspace] = relationship("Workspace")
    assessment: Mapped[Assessment] = relationship("Assessment")
    scan_run: Mapped[ScanRun | None] = relationship("ScanRun")
    attempts_history: Mapped[list["JobAttempt"]] = relationship(
        "JobAttempt",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobAttempt.started_at",
    )

    __table_args__ = (
        UniqueConstraint("run_id", "logical_key", name="uq_job_run_logical_key"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', "
            "'cancelled', 'waiting_provider', 'skipped')",
            name="ck_job_status",
        ),
        CheckConstraint("attempts >= 0", name="ck_job_attempts_non_negative"),
        CheckConstraint("max_attempts >= 1", name="ck_job_max_attempts_positive"),
        CheckConstraint("generation_id >= 0", name="ck_job_generation_id_non_negative"),
        Index("ix_job_claimable", "status", "available_at", "priority", "created_at"),
    )

    def is_terminal(self) -> bool:
        """Check if job reached a terminal state."""
        return self.status in {"completed", "failed", "cancelled", "skipped"}

    def __repr__(self) -> str:
        return (
            f"<Job {self.id} type={self.job_type} status={self.status} "
            f"gen={self.generation_id} attempts={self.attempts}/{self.max_attempts}>"
        )


class JobAttempt(BaseUUIDModel):
    """Execution attempt log for a background job."""

    __tablename__ = "job_attempt"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("job.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    generation_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="running",
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    worker_host: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    job: Mapped[Job] = relationship("Job", back_populates="attempts_history")

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'succeeded', 'failed', 'cancelled')",
            name="ck_job_attempt_status",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<JobAttempt {self.id} job={self.job_id} gen={self.generation_id} "
            f"status={self.status}>"
        )
