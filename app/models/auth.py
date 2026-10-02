"""Authentication and workspace membership database models."""

import uuid
from datetime import datetime

from flask_security.core import RoleMixin, UserMixin
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseUUIDModel, TimestampMixin, utc_now


class UserRoles(BaseUUIDModel):
    """Association model connecting users with roles."""

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("role.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_roles_user_role"),
    )


class Role(BaseUUIDModel, RoleMixin):  # type: ignore[misc]
    """Role model for authorization groups."""

    __tablename__ = "role"

    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    permissions: Mapped[str | None] = mapped_column(String(255), nullable=True)  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class User(BaseUUIDModel, UserMixin):  # type: ignore[misc]
    """User account model for local identity and authentication."""

    __tablename__ = "user"

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    fs_uniquifier: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: uuid.uuid4().hex,
        index=True,
    )
    fs_webauthn_user_handle: Mapped[str | None] = mapped_column(  # type: ignore[assignment]
        String(64),
        unique=True,
        nullable=True,
    )

    # Two-factor / MFA configuration
    tf_primary_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tf_totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Activity tracking & audit timestamps
    create_datetime: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    update_datetime: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
    current_login_at: Mapped[datetime | None] = mapped_column(  # type: ignore[assignment]
        DateTime(timezone=True),
        nullable=True,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(  # type: ignore[assignment]
        DateTime(timezone=True),
        nullable=True,
    )
    current_login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    roles: Mapped[list[Role]] = relationship(  # type: ignore[assignment]
        "Role",
        secondary="user_roles",
        backref="users",
        lazy="selectin",
    )
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"


class Workspace(BaseUUIDModel, TimestampMixin):
    """Workspace tenant container representing an internal team workspace."""

    __tablename__ = "workspace"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    memberships: Mapped[list["Membership"]] = relationship(
        "Membership",
        back_populates="workspace",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Workspace {self.name}>"


class Membership(BaseUUIDModel, TimestampMixin):
    """Membership mapping linking users to workspaces with operational roles."""

    __tablename__ = "membership"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
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
        default="member",
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    workspace: Mapped[Workspace] = relationship("Workspace", back_populates="memberships")
    user: Mapped[User] = relationship("User", back_populates="memberships")

    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_membership_workspace_user"),
        CheckConstraint("role IN ('admin', 'member')", name="ck_membership_role_valid"),
    )

    def __repr__(self) -> str:
        return f"<Membership user={self.user_id} workspace={self.workspace_id} role={self.role}>"
