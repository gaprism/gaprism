"""Assessment and Report grant models for object-level authorization."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.assessment import Assessment, ReportVersion
from app.models.auth import User, Workspace
from app.models.base import BaseUUIDModel, TimestampMixin


class AssessmentGrant(BaseUUIDModel, TimestampMixin):
    """Scoped grant granting a user access to a specific assessment case."""

    __tablename__ = "assessment_grant"

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
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    can_download: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )

    workspace: Mapped[Workspace] = relationship("Workspace")
    assessment: Mapped[Assessment] = relationship("Assessment")
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    grantor: Mapped[User] = relationship("User", foreign_keys=[granted_by])

    __table_args__ = (
        UniqueConstraint("assessment_id", "user_id", name="uq_assessment_grant_assessment_user"),
        CheckConstraint(
            "role IN ('owner', 'analyst', 'reviewer', 'viewer')",
            name="ck_assessment_grant_role",
        ),
    )

    def is_active(self, at_time: datetime | None = None) -> bool:
        """Check if grant is active, not revoked, and not expired."""
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None:
            now = at_time or datetime.now(self.expires_at.tzinfo)
            if now >= self.expires_at:
                return False
        return True

    def __repr__(self) -> str:
        return (
            f"<AssessmentGrant assessment={self.assessment_id} user={self.user_id} "
            f"role={self.role} download={self.can_download}>"
        )


class ReportGrant(BaseUUIDModel, TimestampMixin):
    """Scoped grant granting a user access to a specific issued report version."""

    __tablename__ = "report_grant"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_version.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    can_download: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )

    workspace: Mapped[Workspace] = relationship("Workspace")
    report_version: Mapped[ReportVersion] = relationship("ReportVersion")
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    grantor: Mapped[User] = relationship("User", foreign_keys=[granted_by])

    __table_args__ = (
        UniqueConstraint("report_version_id", "user_id", name="uq_report_grant_version_user"),
    )

    def is_active(self, at_time: datetime | None = None) -> bool:
        """Check if report grant is active, not revoked, and not expired."""
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None:
            now = at_time or datetime.now(self.expires_at.tzinfo)
            if now >= self.expires_at:
                return False
        return True

    def __repr__(self) -> str:
        return (
            f"<ReportGrant version={self.report_version_id} user={self.user_id} "
            f"download={self.can_download}>"
        )
