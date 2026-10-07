"""CheckResult: the outcome of one check — and, while ``queued``, the task that will produce it."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import JSONB_EMPTY_OBJECT, BaseUUIDModel, TimestampMixin, sql_in

# queued/running: work in progress · ok: collected · no_data: asked, nothing there ·
# unavailable: not configured, no key, quota · error: failed · skipped: prerequisite was not ok,
# or the owner switched the check off. These are different outcomes and must never be shown as
# "clean".
CHECK_STATUSES = ("queued", "running", "ok", "no_data", "unavailable", "error", "skipped")
TERMINAL_CHECK_STATUSES = ("ok", "no_data", "unavailable", "error", "skipped")


class CheckResult(BaseUUIDModel, TimestampMixin):
    """One check for one host (or, with ``host_id`` NULL, for the whole domain)."""

    __tablename__ = "check_result"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan.id", ondelete="CASCADE"),
        nullable=False,
    )
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("host.id", ondelete="CASCADE"),
        nullable=True,
    )
    check_key: Mapped[str] = mapped_column(String(48), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=JSONB_EMPTY_OBJECT
    )
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(sql_in("status", CHECK_STATUSES), name="ck_check_result_status"),
        # NULLs are distinct in a plain UNIQUE constraint, so host rows and domain rows get
        # their own partial unique indexes.
        Index(
            "uq_check_result_host",
            "scan_id",
            "host_id",
            "check_key",
            unique=True,
            postgresql_where=text("host_id IS NOT NULL"),
        ),
        Index(
            "uq_check_result_domain",
            "scan_id",
            "check_key",
            unique=True,
            postgresql_where=text("host_id IS NULL"),
        ),
        Index("ix_check_result_claim", "status", "created_at"),
        Index("ix_check_result_host_id", "host_id"),
    )

    @property
    def is_terminal(self) -> bool:
        """True once the check has a final outcome."""
        return self.status in TERMINAL_CHECK_STATUSES

    def __repr__(self) -> str:
        return f"<CheckResult {self.check_key} {self.status} ({self.id})>"
