"""FindingAnnotation model for analyst technical revisions and optimistic locking."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseUUIDModel, TimestampMixin

if TYPE_CHECKING:
    from app.models.check import Finding


class FindingAnnotation(BaseUUIDModel, TimestampMixin):
    """Analyst annotation on technical finding with optimistic concurrency control."""

    __tablename__ = "finding_annotation"

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
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    revised_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    finding: Mapped[Finding] = relationship("Finding", back_populates="annotations")

    __table_args__ = (
        CheckConstraint(
            "revised_severity IS NULL OR revised_severity IN "
            "('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_annotation_revised_severity",
        ),
        CheckConstraint("version_id >= 1", name="ck_annotation_version_positive"),
    )

    def __repr__(self) -> str:
        return (
            f"<FindingAnnotation {self.id} finding={self.finding_id} v={self.version_id} "
            f"false_pos={self.is_false_positive}>"
        )
