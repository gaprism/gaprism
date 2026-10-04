"""Discovery service module."""

from app.service.discovery.ct import (
    CTDiscoveryAdapter,
    CTDiscoveryError,
    CTEntry,
    CTPagedResult,
)
from app.service.discovery.scope import (
    DomainScope,
    ScopeValidationError,
    canonicalise_domain,
    is_in_scope,
)

__all__ = [
    "CTDiscoveryAdapter",
    "CTDiscoveryError",
    "CTEntry",
    "CTPagedResult",
    "DomainScope",
    "ScopeValidationError",
    "canonicalise_domain",
    "is_in_scope",
]
