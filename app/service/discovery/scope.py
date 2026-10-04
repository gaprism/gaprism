"""Domain scope canonicalisation, IDNA translation, and boundary validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.service.discovery.psl import PSL_VERSION, is_public_suffix

NORMALISER_VERSION = "v1"

# Label syntax: alphanumeric with internal hyphens (cannot start or end with hyphen)
_LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ScopeValidationError(ValueError):
    """Raised when an entered domain scope violates syntax or boundary rules."""


@dataclass(frozen=True)
class DomainScope:
    """Immutable, validated domain scope definition."""

    raw_input: str
    canonical: str
    unicode: str
    normaliser_version: str = NORMALISER_VERSION
    psl_version: str = PSL_VERSION


def canonicalise_domain(raw_input: str) -> DomainScope:
    """Canonicalise and strictly validate an entered domain scope.

    Enforces:
    - Stripping of leading/trailing whitespace.
    - Stripping of one optional trailing dot.
    - IDNA translation to lowercase ASCII (punycode `xn--...`).
    - Rejection of URLs, paths, ports, userinfo, IP literals, wildcards, and public suffixes.
    - DNS label length (1..63) and total length (<= 253) validation (RFC 1035 / RFC 1123).
    """
    if not isinstance(raw_input, str):
        raise ScopeValidationError("Domain scope must be a string.")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ScopeValidationError("Domain scope cannot be empty.")

    # Strip single terminal root dot if present
    if cleaned.endswith(".") and not cleaned.endswith(".."):
        cleaned = cleaned[:-1]

    # Strip bracket syntax for IPv6 check if present
    unbracketed = cleaned.strip("[]")
    is_ip = False
    try:
        ipaddress.ip_address(unbracketed)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        raise ScopeValidationError("IP address literals are not allowed as domain scope.")

    # Reject URLs, schemes, paths, userinfo, ports, fragments, query strings
    if "://" in cleaned or cleaned.startswith(("http:", "https:", "ftp:", "file:", "ws:", "wss:")):
        raise ScopeValidationError("URL schemes (e.g. 'https://') are not allowed.")
    if "/" in cleaned or "\\" in cleaned:
        raise ScopeValidationError("Path syntax is not allowed in domain scope.")
    if "@" in cleaned:
        raise ScopeValidationError("Userinfo ('@') is not allowed in domain scope.")
    if ":" in cleaned:
        raise ScopeValidationError("Port numbers or IPv6 bracket syntax are not allowed.")
    if "?" in cleaned or "#" in cleaned:
        raise ScopeValidationError("Query strings and fragments are not allowed.")
    if "*" in cleaned:
        raise ScopeValidationError("Wildcard domains ('*.example.com') are not allowed as scope.")

    # Check for empty labels or consecutive dots before IDNA encoding
    if ".." in cleaned or cleaned.startswith(".") or cleaned.endswith("."):
        raise ScopeValidationError("Domain contains empty labels (consecutive dots).")

    # Pre-check raw label lengths
    raw_labels = cleaned.split(".")
    for raw_label in raw_labels:
        if len(raw_label) > 63:
            raise ScopeValidationError(
                f"Domain label '{raw_label[:10]}...' exceeds maximum length of 63 characters."
            )

    # IDNA encoding to ASCII lowercase
    try:
        canonical = cleaned.encode("idna").decode("ascii").lower()
    except Exception as e:
        raise ScopeValidationError(f"Invalid internationalised domain name: {e}") from e

    # Screen against Public Suffix List (including single-label TLDs)
    if is_public_suffix(canonical):
        raise ScopeValidationError(
            f"'{canonical}' is a public suffix / TLD and cannot be used as an assessment scope."
        )

    # Check total length (max 253 octets per RFC 1035)
    if len(canonical) > 253:
        raise ScopeValidationError(
            f"Domain exceeds maximum allowed length of 253 characters (got {len(canonical)})."
        )

    # Validate labels
    labels = canonical.split(".")
    if len(labels) < 2:
        raise ScopeValidationError(
            "Domain scope must contain at least two labels (e.g. 'example.com')."
        )

    for label in labels:
        if not label:
            raise ScopeValidationError("Domain contains empty labels (consecutive dots).")
        if len(label) > 63:
            raise ScopeValidationError(
                f"Domain label '{label[:10]}...' exceeds maximum length of 63 characters."
            )
        if not _LABEL_REGEX.match(label):
            raise ScopeValidationError(
                f"Domain label '{label}' contains invalid characters or illegal hyphen placement."
            )

    # Screen against Public Suffix List
    if is_public_suffix(canonical):
        raise ScopeValidationError(
            f"'{canonical}' is a public suffix / TLD and cannot be used as an assessment scope."
        )

    # Human-readable unicode form
    try:
        unicode_form = canonical.encode("ascii").decode("idna")
    except Exception:
        unicode_form = canonical

    return DomainScope(
        raw_input=raw_input,
        canonical=canonical,
        unicode=unicode_form,
        normaliser_version=NORMALISER_VERSION,
        psl_version=PSL_VERSION,
    )


def is_in_scope(hostname: str, scope: DomainScope | str) -> bool:
    """Check if a concrete hostname belongs strictly to the defined domain scope.

    Enforces strict dot-boundary matching:
    - 'sub.example.com' and 'example.com' are in scope for 'example.com'.
    - 'notexample.com' and 'example.com.evil.com' are rejected.
    """
    if isinstance(scope, DomainScope):
        scope_canonical = scope.canonical
    else:
        try:
            scope_canonical = canonicalise_domain(scope).canonical
        except ScopeValidationError:
            # Fallback direct lowercase ASCII normalisation if raw string is provided
            scope_canonical = scope.strip().rstrip(".").lower()

    if not isinstance(hostname, str) or not hostname.strip():
        return False

    cleaned_host = hostname.strip()
    if cleaned_host.endswith(".") and not cleaned_host.endswith(".."):
        cleaned_host = cleaned_host[:-1]

    try:
        host_canonical = cleaned_host.encode("idna").decode("ascii").lower()
    except Exception:
        return False

    # Exact equality or dot-label subdomain
    if host_canonical == scope_canonical:
        return True

    return host_canonical.endswith("." + scope_canonical)
