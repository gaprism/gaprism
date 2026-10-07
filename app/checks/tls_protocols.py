"""TLS protocols and cipher suites: which versions does the server accept, and which weak kinds of
suites?

Needs the DNS check: the handshakes go to the first public address found there, so nothing is
resolved a second time and a private answer can never be connected to. Each question is one
handshake in which only the version (TLS 1.0, 1.1, 1.2, 1.3) or only the kind of suites
(anonymous or without encryption, key exchange with the server's RSA key) is offered, and nothing is
sent after the handshake. The certificate is not verified for this (the TLS check does that); the
question is what the server is willing to negotiate.

What this client cannot offer (SSLv2, SSLv3, RC4, DES, 3DES, export suites) is listed in
``not_tested`` with the OpenSSL it asked with, so that a silence is never read as "not
supported". A host where not even one handshake succeeded is reported as such and judged by no rule:
a server that refused every question says nothing about what it supports.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from runner.dns import SSRFBlockedError
from runner.tls_protocols import (
    NOT_TESTED,
    Attempt,
    TLSProtocolsResult,
    forward_secret,
    probe_tls_protocols,
)

PORT = 443
SOURCE = "tls-probe"
MAX_ATTEMPT_SECONDS = 5.0

Prober = Callable[..., TLSProtocolsResult]


def _reason_for_silence(result: TLSProtocolsResult) -> str:
    reasons = {attempt.reason for attempt in result.attempts}
    if "timeout" in reasons:
        return "timeout"
    if reasons == {"not_tls"}:
        return "not_tls"
    return "no_handshake"


def _entry(attempt: Attempt) -> dict[str, Any]:
    """One answer as stored; an accepted one also says whether its suite gives forward secrecy."""
    entry = attempt.to_dict()
    entry["forward_secret"] = (
        forward_secret(attempt.cipher) if attempt.status == "accepted" and attempt.cipher else None
    )
    return entry


def outcome_from_protocols(result: TLSProtocolsResult) -> CheckOutcome:
    """Turn the prober's answers into a typed outcome.

    Nothing listening is ``no_data``; a server that completed no handshake at all is an
    ``error`` (inconclusive, never "no protocols"); otherwise ``ok`` with every answer kept.
    """
    base: dict[str, Any] = {"ip": result.connected_ip, "port": result.port}
    if result.refused:
        return CheckOutcome("no_data", "refused", base, SOURCE)
    data = {
        **base,
        "versions": [_entry(attempt) for attempt in result.versions],
        "suites": [_entry(attempt) for attempt in result.suites],
        "accepted": result.accepted(),
        "not_tested": list(NOT_TESTED),
        "openssl": result.openssl,
    }
    if not result.reachable:
        return CheckOutcome("error", _reason_for_silence(result), data, SOURCE)
    return CheckOutcome("ok", data=data, source=SOURCE)


class TlsProtocolsCheck:
    """Ask a host which TLS versions and kinds of cipher suites it accepts (port 443)."""

    key = "tls_protocols"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(self, prober: Prober | None = None) -> None:
        self._prober = prober or probe_tls_protocols

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        addresses = [str(ip) for ip in dns.data.get("addresses", [])] if dns else []
        if not addresses:
            blocked = dns.data.get("blocked", []) if dns else []
            return CheckOutcome("skipped", "no_public_address", {"blocked": blocked})
        timeout = min(
            float(ctx.config.get("EGRESS_CONNECT_TIMEOUT_SEC", 10.0)), MAX_ATTEMPT_SECONDS
        )
        try:
            result = self._prober(
                ctx.hostname or "", PORT, ip_override=addresses[0], timeout=timeout
            )
        except SSRFBlockedError:
            return CheckOutcome("error", "blocked_destination", {"ip": addresses[0]})
        return outcome_from_protocols(result)
