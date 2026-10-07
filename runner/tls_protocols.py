"""Which TLS protocol versions and kinds of cipher suites does a server accept?

Every question is one handshake in which the client offers only the version, or only the kind of
suites, that is being asked about; nothing is sent after the handshake. The connection goes to the
screened address the caller passes in (the DNS check's), like the certificate prober's. The
certificate is not verified here: nothing is exchanged and nothing from the connection is trusted,
because the question is what the server is willing to *negotiate*, not who it is (the certificate
prober answers that, and verifies).

What can be asked depends on the OpenSSL this client is built with. Today's builds cannot offer
SSLv2, SSLv3, RC4, DES, 3DES or export suites at all, and offer TLS 1.0 and 1.1 only with the
security level lowered, so those are not asked: ``NOT_TESTED`` says so and the result carries the
OpenSSL version, instead of a silence that reads like "not supported". A question the client
cannot put is ``not_testable``; a server that answers with an alert or hangs up is ``rejected``;
a timeout or a network problem is ``unknown``. A result in which not even one handshake succeeded
says nothing about the server, and callers must not draw conclusions from it (``reachable``).
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from runner.dns import SSRFBlockedError, is_ip_public
from runner.quiet import silenced

# The versions asked about, most useful control first: a server that accepts neither TLS 1.2 nor
# TLS 1.3 from this client is not a good basis for saying that it does not support TLS 1.0.
VERSIONS = ("TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1")
ASCENDING = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_LEVELS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
# The suites offered alongside a version: what a client of that age would offer (OpenSSL's
# DEFAULT), with the security level lowered so that the old versions can be offered at all.
LEGACY_SUITES = "DEFAULT:@SECLEVEL=0"
# The kind of suites asked about, with versions 1.0 to 1.2 allowed: ``anonymous_or_null`` has no
# authentication (anyone can be the server) or no encryption at all. (Accepting suites with the
# server's RSA key exchange is common and says little; what matters is whether the server *chooses*
# one when it could have had forward secrecy, and the TLS 1.2 handshake above shows that.)
SUITE_KINDS = {"anonymous_or_null": "aNULL:eNULL:@SECLEVEL=0"}
NOT_TESTED = (
    "SSLv2",
    "SSLv3",
    "RC4",
    "DES",
    "3DES",
    "export suites",
    "the strength of Diffie-Hellman parameters",
)
DEPRECATED_VERSION = r"ssl\.TLSVersion\.\w+ is deprecated"

# What a refusal looks like from the client's side (``ssl.SSLError.reason``).
_NOT_OFFERED = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE")
_NOT_TLS = ("WRONG_VERSION_NUMBER", "HTTP_REQUEST", "HTTPS_PROXY_REQUEST", "UNKNOWN_PROTOCOL")

MAX_BUDGET_SECONDS = 60.0

Monotonic = Callable[[], float]


@dataclass(frozen=True)
class Attempt:
    """The answer to one question."""

    key: str  # a version ("TLSv1.2") or a kind of suites ("static_rsa")
    status: str  # accepted | rejected | unknown | not_testable
    version: str | None = None  # what was negotiated, when accepted
    cipher: str | None = None
    reason: str | None = None  # alert | closed | not_tls | refused | timeout | ... (a stable code)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "status": self.status,
            "version": self.version,
            "cipher": self.cipher,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TLSProtocolsResult:
    hostname: str
    port: int
    connected_ip: str
    versions: list[Attempt] = field(default_factory=list)
    suites: list[Attempt] = field(default_factory=list)
    openssl: str = ssl.OPENSSL_VERSION
    collected_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )

    @property
    def attempts(self) -> list[Attempt]:
        return [*self.versions, *self.suites]

    @property
    def reachable(self) -> bool:
        """Did at least one handshake succeed? Without it nothing here is evidence."""
        return any(attempt.status == "accepted" for attempt in self.attempts)

    @property
    def refused(self) -> bool:
        """Nothing listens on the port (the first connection was refused)."""
        return any(attempt.reason == "refused" for attempt in self.attempts)

    def accepted(self) -> list[str]:
        return [a.key for a in self.versions if a.status == "accepted"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "connected_ip": self.connected_ip,
            "versions": [a.to_dict() for a in self.versions],
            "suites": [a.to_dict() for a in self.suites],
            "openssl": self.openssl,
            "collected_at": self.collected_at.isoformat(),
        }


def forward_secret(cipher: str) -> bool:
    """Does a negotiated suite give forward secrecy? (An ephemeral key exchange: ECDHE, DHE, and
    every TLS 1.3 suite, whose names start with ``TLS_``.)"""
    return cipher.startswith(("ECDHE-", "DHE-", "EDH-", "TLS_"))


def _classify(exc: ssl.SSLError) -> tuple[str, str]:
    """(status, reason code) of a failed handshake, from the point of view of the client."""
    reason = (exc.reason or "").upper()
    if "timed out" in str(exc).lower():
        return "unknown", "timeout"  # older Pythons report a handshake timeout as an SSLError
    if reason in _NOT_OFFERED:
        return "not_testable", "unsupported_by_client"
    if isinstance(exc, ssl.SSLEOFError) or "EOF" in reason:
        return "rejected", "closed"  # the server hung up instead of answering
    if "ALERT" in reason or reason in ("NO_SHARED_CIPHER", "UNSUPPORTED_PROTOCOL"):
        return "rejected", "alert"
    if reason in _NOT_TLS:
        return "rejected", "not_tls"
    return "unknown", "tls_error"


def _context(minimum: str, maximum: str, suites: str | None) -> ssl.SSLContext:
    """A client context that offers versions ``minimum`` to ``maximum`` and ``suites``.

    Raises ``ValueError`` or ``ssl.SSLError`` when this build cannot offer that.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # no verification: see the module docstring
    context.verify_mode = ssl.CERT_NONE
    with silenced(DeprecationWarning, DEPRECATED_VERSION):
        context.minimum_version = _LEVELS[minimum]
        context.maximum_version = _LEVELS[maximum]
    if suites is not None:
        context.set_ciphers(suites)
    return context


def _offer(
    key: str,
    connect_host: str,
    port: int,
    server_name: str,
    timeout: float,
    minimum: str,
    maximum: str,
    suites: str | None,
) -> Attempt:
    context = None
    # A build that cannot offer the lowest version of a range asks with the lowest it has.
    for lowest in ASCENDING[ASCENDING.index(minimum) : ASCENDING.index(maximum) + 1]:
        try:
            context = _context(lowest, maximum, suites)
            break
        except (ValueError, ssl.SSLError):
            continue
    if context is None:
        return Attempt(key, "not_testable", reason="unsupported_by_client")
    try:
        raw = socket.create_connection((connect_host, port), timeout=timeout)
    except ConnectionRefusedError:
        return Attempt(key, "unknown", reason="refused")
    except TimeoutError:
        return Attempt(key, "unknown", reason="timeout")
    except OSError:
        return Attempt(key, "unknown", reason="connection_failed")
    try:
        with raw:
            if ipaddress.ip_address(raw.getpeername()[0]) != ipaddress.ip_address(connect_host):
                raise SSRFBlockedError("TLS connection peer differs from screened IP.")
            with context.wrap_socket(raw, server_hostname=server_name) as secured:
                cipher = secured.cipher()
                return Attempt(
                    key,
                    "accepted",
                    version=secured.version(),
                    cipher=cipher[0] if cipher else None,
                )
    except ssl.SSLError as exc:
        status, reason = _classify(exc)
        return Attempt(key, status, reason=reason)
    except TimeoutError:
        return Attempt(key, "unknown", reason="timeout")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return Attempt(key, "rejected", reason="closed")
    except (OSError, ValueError, UnicodeError):  # ValueError: a name that cannot be sent as SNI
        return Attempt(key, "unknown", reason="connection_failed")


def probe_tls_protocols(
    hostname: str,
    port: int = 443,
    *,
    ip_override: str,
    timeout: float = 5.0,
    budget: float = MAX_BUDGET_SECONDS,
    monotonic: Monotonic = time.monotonic,
) -> TLSProtocolsResult:
    """Ask a TLS server which protocol versions and kinds of suites it accepts.

    ``ip_override`` must be a numeric public address (the DNS check's): ``SSRFBlockedError``
    otherwise. The questions stop after the first one if the port refuses or does not answer, and
    after ``budget`` seconds; what was not asked is ``unknown`` (``budget_exceeded``).
    """
    try:
        address = ipaddress.ip_address(ip_override)
    except ValueError as exc:
        raise SSRFBlockedError("TLS destination must be a numeric public IP.") from exc
    if not is_ip_public(address):
        raise SSRFBlockedError("TLS destination is not a public IP.")
    if not 1 <= port <= 65535 or not 0 < timeout <= 30:
        raise ValueError("Invalid TLS port or timeout.")
    target = hostname.strip().lower()
    connect_host = str(address)
    deadline = monotonic() + budget

    questions: list[tuple[str, str, str, str | None, bool]] = [
        # (key, minimum, maximum, suites, is a version question)
        *(
            (version, version, version, None if version == "TLSv1.3" else LEGACY_SUITES, True)
            for version in VERSIONS
        ),
        *((kind, "TLSv1", "TLSv1.2", SUITE_KINDS[kind], False) for kind in SUITE_KINDS),
    ]
    versions: list[Attempt] = []
    suites: list[Attempt] = []
    stop: str | None = None
    for key, minimum, maximum, offered, is_version in questions:
        if stop is not None:
            attempt = Attempt(key, "unknown", reason=stop)
        elif monotonic() > deadline:
            attempt = Attempt(key, "unknown", reason="budget_exceeded")
        else:
            attempt = _offer(key, connect_host, port, target, timeout, minimum, maximum, offered)
            if attempt.status == "unknown" and attempt.reason in (
                "refused",
                "timeout",
                "connection_failed",
            ):
                stop = (
                    attempt.reason
                )  # nothing to talk to: do not spend a timeout on every question
        (versions if is_version else suites).append(attempt)
    return TLSProtocolsResult(
        hostname=target, port=port, connected_ip=connect_host, versions=versions, suites=suites
    )
