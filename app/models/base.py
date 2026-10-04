"""Base database model classes, mixins and small helpers shared by all models."""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import DateTime, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql.elements import TextClause

from app.extensions import db

JSONB_EMPTY_OBJECT: TextClause = text("'{}'::jsonb")
JSONB_EMPTY_ARRAY: TextClause = text("'[]'::jsonb")


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def sql_in(column: str, values: Sequence[str]) -> str:
    """Render ``column IN ('a', 'b')`` for CHECK constraints from trusted module constants."""
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class BaseUUIDModel(db.Model):  # type: ignore[name-defined]
    """Abstract base model with application-generated UUID primary key."""

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )


class TimestampMixin:
    """Mixin adding created_at and updated_at UTC timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
