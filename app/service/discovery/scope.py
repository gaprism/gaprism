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
    """Raised when an entered domain violates syntax or boundary rules.

    The message is written for the person who typed the domain: what happened, and what to do about
    it. ``message`` is the English text with %(name)s placeholders and ``params`` fill them, so that
    whoever shows it translates the text first and fills it in after: ``_(e.message, **e.params)``.
    ``str(e)`` is the English sentence, for logs and the command line. This module stays free of
    Flask: the discovery check imports it too.
    """

    def __init__(self, message: str, **params: object) -> None:
        super().__init__(message % params if params else message)
        self.message = message
        self.params = params


EMPTY = "Enter the vendor's domain, for example example.com."
EMPTY_PART = (
    "The domain has an empty part: two dots in a row, or a dot at the start. Check the spelling."
)
LONG_PART = (
    'A part of the domain ("%(start)s...") has more than 63 characters, '
    "which a domain name cannot have. Check the spelling."
)


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
        raise ScopeValidationError("A domain must be text.")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ScopeValidationError(EMPTY)

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
        raise ScopeValidationError(
            "That is an IP address, not a domain name. "
            "Enter the vendor's domain name instead, for example example.com."
        )

    # Reject URLs, schemes, paths, userinfo, ports, fragments, query strings
    if "://" in cleaned or cleaned.startswith(("http:", "https:", "ftp:", "file:", "ws:", "wss:")):
        raise ScopeValidationError('Enter the domain only, without "https://" or another scheme.')
    if "/" in cleaned or "\\" in cleaned:
        raise ScopeValidationError(
            "Enter the domain only, without a path. Remove the slash and everything after it."
        )
    if "@" in cleaned:
        raise ScopeValidationError(
            'Enter the domain only. Remove the "@" and everything before it.'
        )
    if ":" in cleaned:
        raise ScopeValidationError(
            "Enter the domain only, without a port number. Remove the colon and what follows it."
        )
    if "?" in cleaned or "#" in cleaned:
        raise ScopeValidationError(
            'Enter the domain only. Remove the "?" or "#" and everything after it.'
        )
    if "*" in cleaned:
        raise ScopeValidationError(
            "Enter a single domain, such as example.com. "
            'A wildcard such as "*.example.com" is not accepted.'
        )

    # Check for empty labels or consecutive dots before IDNA encoding
    if ".." in cleaned or cleaned.startswith(".") or cleaned.endswith("."):
        raise ScopeValidationError(EMPTY_PART)

    # Pre-check raw label lengths
    raw_labels = cleaned.split(".")
    for raw_label in raw_labels:
        if len(raw_label) > 63:
            raise ScopeValidationError(LONG_PART, start=raw_label[:10])

    # IDNA encoding to ASCII lowercase
    try:
        canonical = cleaned.encode("idna").decode("ascii").lower()
    except Exception as e:
        raise ScopeValidationError(
            "This is not a valid internationalised domain name. Check the spelling."
        ) from e

    # Screen against Public Suffix List (including single-label TLDs)
    if is_public_suffix(canonical):
        raise ScopeValidationError(
            '"%(domain)s" is a top-level domain or public suffix, '
            "not one organisation's domain. Enter the vendor's own domain, "
            "for example vendor.%(domain)s.",
            domain=canonical,
        )

    # Check total length (max 253 octets per RFC 1035)
    if len(canonical) > 253:
        raise ScopeValidationError(
            "The domain has %(length)s characters. A domain name has at most 253. "
            "Check what you entered.",
            length=len(canonical),
        )

    # Validate labels
    labels = canonical.split(".")
    if len(labels) < 2:
        raise ScopeValidationError(
            "Enter a full domain name with at least two parts, for example example.com."
        )

    for label in labels:
        if not label:
            raise ScopeValidationError(EMPTY_PART)
        if len(label) > 63:
            raise ScopeValidationError(LONG_PART, start=label[:10])
        if not _LABEL_REGEX.match(label):
            raise ScopeValidationError(
                '"%(part)s" cannot be part of a domain name. '
                "Use letters, digits and hyphens, with no hyphen at the start or end of a part.",
                part=label,
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
