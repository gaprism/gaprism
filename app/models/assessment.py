"""Assessment: a vendor domain under review by the team."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseUUIDModel, TimestampMixin, sql_in

if TYPE_CHECKING:
    from app.models.scan import Scan

VISIBILITIES = ("private", "team")


class Assessment(BaseUUIDModel, TimestampMixin):
    """A domain the team reviews; owns its scans and the decisions taken on its findings."""

    __tablename__ = "assessment"

    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    domain_display: Mapped[str] = mapped_column(String(253), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, default="private")
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="assessment",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Scan.created_at.desc()",
    )

    __table_args__ = (
        CheckConstraint(sql_in("visibility", VISIBILITIES), name="ck_assessment_visibility"),
    )

    def __repr__(self) -> str:
        return f"<Assessment {self.domain} ({self.id})>"
