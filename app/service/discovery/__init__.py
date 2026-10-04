"""Discovery service module."""

from app.service.discovery.scope import (
    DomainScope,
    ScopeValidationError,
    canonicalise_domain,
    is_in_scope,
)
from app.service.discovery.service import (
    DiscoveredHost,
    DiscoveryResult,
    merge_outcomes,
    normalise_name,
    run_discovery,
)

__all__ = [
    "DiscoveredHost",
    "DiscoveryResult",
    "DomainScope",
    "ScopeValidationError",
    "canonicalise_domain",
    "is_in_scope",
    "merge_outcomes",
    "normalise_name",
    "run_discovery",
]
