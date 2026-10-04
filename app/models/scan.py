"""Scan: one execution of all checks for an assessment (a re-scan creates a new row)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import JSONB_EMPTY_OBJECT, BaseUUIDModel, TimestampMixin, sql_in

if TYPE_CHECKING:
    from app.models.assessment import Assessment

SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")
TERMINAL_SCAN_STATUSES = ("completed", "partial", "failed", "cancelled")


class Scan(BaseUUIDModel, TimestampMixin):
    """One run of discovery and checks; terminal scans are never modified again."""

    __tablename__ = "scan"

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
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    options: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=JSONB_EMPTY_OBJECT
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    assessment: Mapped[Assessment] = relationship("Assessment", back_populates="scans")

    __table_args__ = (CheckConstraint(sql_in("status", SCAN_STATUSES), name="ck_scan_status"),)

    @property
    def is_terminal(self) -> bool:
        """True once the scan reached a final state."""
        return self.status in TERMINAL_SCAN_STATUSES

    def __repr__(self) -> str:
        return f"<Scan {self.id} {self.status}>"
