"""Audit event: one line of the audit log, written in the transaction of what it records."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import JSONB_EMPTY_OBJECT, BaseUUIDModel, sql_in, utc_now

AUDIT_SOURCES = ("web", "cli")


class AuditEvent(BaseUUIDModel):
    """Who did what, when, and to what. The application only ever adds rows (and removes the
    oldest ones when the retention period has passed): an entry is never edited.

    ``actor_email`` keeps the address as it was, and ``details`` the name of the domain, so that an
    entry still reads right after the account or the assessment is gone (the links then become
    null). ``details`` holds small facts and never a secret or text somebody typed.
    """

    __tablename__ = "audit_event"

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    source: Mapped[str] = mapped_column(String(8), nullable=False, default="web")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id", ondelete="SET NULL"), nullable=True
    )
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=JSONB_EMPTY_OBJECT
    )
    remote_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        CheckConstraint(sql_in("source", AUDIT_SOURCES), name="ck_audit_event_source"),
        Index("ix_audit_event_occurred_at", "occurred_at"),
        Index("ix_audit_event_assessment_id_occurred_at", "assessment_id", "occurred_at"),
        Index("ix_audit_event_actor_id_occurred_at", "actor_id", "occurred_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent {self.action} {self.occurred_at}>"
