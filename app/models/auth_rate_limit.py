"""Persistent, pseudonymous rate-limit buckets for authentication failures."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db
from app.models.base import utc_now


class AuthRateLimitBucket(db.Model):  # type: ignore[misc, name-defined]
    """Sliding authentication-failure bucket without raw email or IP storage."""

    __tablename__ = "auth_rate_limit_bucket"

    bucket_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    bucket_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint("bucket_kind IN ('ip', 'principal')", name="ck_auth_bucket_kind"),
        CheckConstraint("failures >= 0", name="ck_auth_bucket_failures_non_negative"),
    )
