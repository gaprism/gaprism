"""Host: one concrete hostname reviewed in a scan."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import JSONB_EMPTY_ARRAY, BaseUUIDModel, TimestampMixin, sql_in

# ct: found in Certificate Transparency · apex: the entered domain itself · manual: added by an
# analyst · fallback: apex/www used because every CT source failed.
HOST_SOURCES = ("ct", "apex", "manual", "fallback")


class Host(BaseUUIDModel, TimestampMixin):
    """A concrete hostname (never a wildcard pattern) that belongs to a scan."""

    __tablename__ = "host"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan.id", ondelete="CASCADE"),
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="ct")
    ct_sources: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=JSONB_EMPTY_ARRAY
    )
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("scan_id", "hostname", name="uq_host_scan_hostname"),
        CheckConstraint(sql_in("source", HOST_SOURCES), name="ck_host_source"),
    )

    def __repr__(self) -> str:
        return f"<Host {self.hostname} ({self.id})>"
