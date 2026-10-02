"""ScanRun database model for assessment executions."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.assessment import Assessment
from app.models.auth import User, Workspace
from app.models.base import BaseUUIDModel, TimestampMixin


class ScanRun(BaseUUIDModel, TimestampMixin):
    """Execution run tracking background assessment jobs and state."""

    __tablename__ = "scan_run"

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
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    request_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    target_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="queued",
        nullable=False,
        index=True,
    )
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    total_hosts_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    redacted_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    profile_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0")

    workspace: Mapped[Workspace] = relationship("Workspace")
    assessment: Mapped[Assessment] = relationship("Assessment")
    requester: Mapped[User] = relationship("User", foreign_keys=[requested_by])

    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "request_key",
            name="uq_scan_run_assessment_request_key",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', "
            "'cancelled', 'failed', 'waiting_provider')",
            name="ck_scan_run_status",
        ),
        CheckConstraint("revision >= 1", name="ck_scan_run_revision_positive"),
        CheckConstraint(
            "total_hosts_discovered >= 0",
            name="ck_scan_run_total_hosts_discovered_positive",
        ),
    )

    def is_terminal(self) -> bool:
        """Check if scan run reached a terminal state."""
        return self.status in {"completed", "partial", "cancelled", "failed"}

    def __repr__(self) -> str:
        return f"<ScanRun {self.id} target={self.target_domain} status={self.status}>"
