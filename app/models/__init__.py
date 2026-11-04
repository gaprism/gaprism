"""Database models. Importing this package registers every model with SQLAlchemy metadata."""

from app.models.assessment import Assessment
from app.models.audit_event import AuditEvent
from app.models.auth import Role, User, UserRoles
from app.models.auth_rate_limit import AuthRateLimitBucket
from app.models.base import BaseUUIDModel, TimestampMixin, utc_now
from app.models.check_result import CheckResult
from app.models.finding import Finding, FindingDisposition
from app.models.host import Host
from app.models.invitation import UserInvitation
from app.models.provider_cache import ProviderCache
from app.models.scan import Scan
from app.models.user_image import UserImage

__all__ = [
    "Assessment",
    "AuditEvent",
    "AuthRateLimitBucket",
    "BaseUUIDModel",
    "CheckResult",
    "Finding",
    "FindingDisposition",
    "Host",
    "ProviderCache",
    "Role",
    "Scan",
    "TimestampMixin",
    "User",
    "UserImage",
    "UserInvitation",
    "UserRoles",
    "utc_now",
]
