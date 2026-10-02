"""Discovery and observation database models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseUUIDModel, TimestampMixin


class Host(BaseUUIDModel, TimestampMixin):
    """Concrete host target discovered within an assessment scope."""

    __tablename__ = "host"

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
    name_ascii: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name_display: Mapped[str] = mapped_column(String(255), nullable=False)

    __table_args__ = (
        UniqueConstraint("assessment_id", "name_ascii", name="uq_host_assessment_name_ascii"),
    )

    def __repr__(self) -> str:
        return f"<Host {self.name_ascii} ({self.id})>"


class RunHost(BaseUUIDModel, TimestampMixin):
    """Link table associating a concrete Host with a specific ScanRun execution."""

    __tablename__ = "run_host"

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
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_run.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("host.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    discovery_source: Mapped[str] = mapped_column(String(64), default="ct_log", nullable=False)
    eligibility: Mapped[str] = mapped_column(String(32), default="eligible", nullable=False)
    exclusion_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_collected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    host: Mapped[Host] = relationship("Host", lazy="joined")

    __table_args__ = (
        UniqueConstraint("run_id", "host_id", name="uq_run_host_run_host_id"),
        CheckConstraint(
            "eligibility IN ('eligible', 'ineligible', 'excluded')",
            name="ck_run_host_eligibility",
        ),
    )

    def __repr__(self) -> str:
        return f"<RunHost run={self.run_id} host={self.host_id} elig={self.eligibility}>"


class CTNameObservation(BaseUUIDModel, TimestampMixin):
    """Immutable Certificate Transparency log observation (including wildcard patterns)."""

    __tablename__ = "ct_name_observation"

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
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_run.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name_pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint("run_id", "name_pattern", name="uq_ct_obs_run_name_pattern"),
        CheckConstraint("entry_count >= 0", name="ck_ct_obs_entry_count_non_negative"),
    )

    def __repr__(self) -> str:
        return f"<CTNameObservation pattern={self.name_pattern} wildcard={self.is_wildcard}>"
