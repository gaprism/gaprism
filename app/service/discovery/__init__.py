"""Discovery service module."""

from app.service.discovery.ct import (
    CTDiscoveryAdapter,
    CTDiscoveryError,
    CTEntry,
    CTPagedResult,
    DiscoveryPageCommitResult,
    commit_discovery_page,
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
    "DiscoveryPageCommitResult",
    "DomainScope",
    "ScopeValidationError",
    "canonicalise_domain",
    "commit_discovery_page",
    "is_in_scope",
]
