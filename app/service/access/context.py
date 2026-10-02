"""ActorContext data structure for authenticated user and workspace session identity."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.models.auth import User


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(UTC)


@dataclass(frozen=True)
class ActorContext:
    """Immutable security context constructed from verified session and membership."""

    user_id: uuid.UUID
    workspace_id: uuid.UUID
    auth_freshness: datetime
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    is_admin: bool = False

    @classmethod
    def from_user(
        cls,
        user: User,
        workspace_id: uuid.UUID,
        auth_freshness: datetime | None = None,
        correlation_id: str | None = None,
    ) -> "ActorContext":
        """Construct ActorContext from User entity and verified active workspace membership."""
        # Find active membership in the designated workspace
        matching_membership = next(
            (
                m
                for m in user.memberships
                if m.workspace_id == workspace_id and m.active
            ),
            None,
        )

        is_admin = False
        if matching_membership and matching_membership.role == "admin":
            is_admin = True
        elif any(role.name == "admin" for role in user.roles):
            is_admin = True

        return cls(
            user_id=user.id,
            workspace_id=workspace_id,
            auth_freshness=auth_freshness or utc_now(),
            correlation_id=correlation_id or uuid.uuid4().hex,
            is_admin=is_admin,
        )
