"""One-time links: an invitation for a new account, or a reset for an existing one."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.auth import User
from app.models.base import BaseUUIDModel, sql_in, utc_now

PURPOSES = ("invite", "reset")


class UserInvitation(BaseUUIDModel):
    """The one link an account has for a purpose.

    The link itself is never stored, only its SHA-256. The row is deleted when the link is used,
    so an account that still has an ``invite`` row has not accepted its invitation yet.
    """

    __tablename__ = "user_invitation"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(8), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    reset_authenticator: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )  # empty when a link is made on the command line
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("user_id", "purpose", name="uq_user_invitation_user_purpose"),
        CheckConstraint(sql_in("purpose", PURPOSES), name="ck_user_invitation_purpose"),
    )

    def __repr__(self) -> str:
        return f"<UserInvitation {self.purpose} for {self.user_id}>"
