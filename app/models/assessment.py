"""Assessment, Report, and ReportVersion database models."""

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

from app.models.base import BaseUUIDModel, TimestampMixin


class Assessment(BaseUUIDModel, TimestampMixin):
    """Assessment case container for target domain evaluations."""

    __tablename__ = "assessment"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    supplier_label: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_ascii: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scope_display: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    state: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        CheckConstraint("state IN ('active', 'archived')", name="ck_assessment_state"),
        CheckConstraint("revision >= 1", name="ck_assessment_revision_positive"),
    )

    def __repr__(self) -> str:
        return f"<Assessment {self.scope_ascii} ({self.id})>"


class Report(BaseUUIDModel, TimestampMixin):
    """Report logical grouping container for an assessment."""

    __tablename__ = "report"

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
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )

    versions: Mapped[list["ReportVersion"]] = relationship(
        "ReportVersion",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="ReportVersion.version_number",
    )

    def __repr__(self) -> str:
        return f"<Report {self.id} assessment={self.assessment_id}>"


class ReportVersion(BaseUUIDModel, TimestampMixin):
    """Frozen, immutable snapshot and state representation of an issued report."""

    __tablename__ = "report_version"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    snapshot_schema: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0")
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(
        String(32),
        default="preparing",
        nullable=False,
    )
    preparer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0")
    issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    report: Mapped[Report] = relationship("Report", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("report_id", "version_number", name="uq_report_version_report_number"),
        CheckConstraint(
            "state IN ('preparing', 'draft', 'issuing', 'issued')",
            name="ck_report_version_state",
        ),
        CheckConstraint("version_number >= 1", name="ck_report_version_number_positive"),
    )

    def __repr__(self) -> str:
        return f"<ReportVersion {self.id} v{self.version_number} state={self.state}>"
