"""The picture a person chose for their profile."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, LargeBinary, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseUUIDModel


class UserImage(BaseUUIDModel):
    """The one picture of an account: replaced when it changes, deleted when it is removed.

    ``content`` is what ``app.service.images`` made of the upload (a small square WebP), never the
    upload itself. It has a table of its own so that the account row, which every request loads,
    stays small; ``user.picture_version`` says whether there is a picture and which one.
    """

    __tablename__ = "user_image"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    __table_args__ = (UniqueConstraint("user_id", name="uq_user_image_user_id"),)
