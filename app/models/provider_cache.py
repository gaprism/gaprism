"""ProviderCache: short-lived answers from external providers, so re-scans do not repeat calls."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db
from app.models.base import JSONB_EMPTY_OBJECT, sql_in, utc_now

# Only definitive answers are cached; errors and quota/availability problems never are.
CACHE_STATUSES = ("ok", "no_data")


class ProviderCache(db.Model):  # type: ignore[name-defined]
    """Cached provider answer for one (provider, key), e.g. ("shodan", "93.184.216.34")."""

    __tablename__ = "provider_cache"

    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=JSONB_EMPTY_OBJECT
    )
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint(sql_in("status", CACHE_STATUSES), name="ck_provider_cache_status"),
        Index("ix_provider_cache_fetched_at", "fetched_at"),
    )
