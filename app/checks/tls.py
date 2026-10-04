"""TLS: the certificate a host presents on port 443, and whether a client would trust it.

Needs the DNS check: the connection goes to the first public address found there, so nothing is
resolved a second time and a private answer can never be connected to. Verification is never
switched off; when it fails, the prober reads the certificate through a separate, labelled
(``forensic``) connection so the report can still say *what* was wrong with it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from runner.dns import SSRFBlockedError
from runner.tls import TLSProbeResult, probe_tls_endpoint

PORT = 443
MAX_SANS = 100  # stored; the full count is kept in ``san_count``
MAX_TEXT = 200

# (start of the runner's failure reason, our code). Order matters: the first match wins.
_FAILURE_CODES = (
    ("CERTIFICATE_EXPIRED", "expired"),
    ("CERTIFICATE_NOT_YET_VALID", "not_yet_valid"),
    ("HOSTNAME_MISMATCH", "hostname_mismatch"),
    ("UNTRUSTED_ROOT", "untrusted"),
    ("CERTIFICATE_VERIFY_FAILED", "verify_failed"),
    ("TLS_HANDSHAKE_FAILED", "handshake_failed"),
    ("TIMEOUT", "timeout"),
    ("CONNECTION_REFUSED", "refused"),
    ("CONNECTION_FAILED", "connection_failed"),
)

Prober = Callable[..., TLSProbeResult]


def failure_codes(reasons: list[str]) -> list[str]:
    """The prober's failure reasons as stable lower-case codes (deduplicated, in order)."""
    codes: list[str] = []
    for reason in reasons:
        code = next((c for prefix, c in _FAILURE_CODES if reason.startswith(prefix)), "other")
        if code not in codes:
            codes.append(code)
    return codes


def _text(value: str | None) -> str | None:
    return value[:MAX_TEXT] if value else value


def outcome_from_probe(result: TLSProbeResult) -> CheckOutcome:
    """Turn a probe result into a typed outcome.

    A certificate that was read is ``ok`` even when it is bad: the facts were collected and
    ``verified``/``failures`` say what is wrong. No certificate at all is ``no_data`` when
    nothing listens on the port, and an ``error`` otherwise.
    """
    codes = failure_codes(result.failure_reasons)
    base: dict[str, Any] = {"ip": result.connected_ip, "port": result.port}
    if result.fingerprint_sha256 is None:
        if "refused" in codes:
            return CheckOutcome("no_data", "refused", base, "tls-probe")
        return CheckOutcome(
            "error",
            codes[0] if codes else "no_certificate",
            {**base, "failures": codes},
            "tls-probe",
        )
    data = {
        **base,
        "verified": result.is_valid,
        "failures": codes,
        "forensic": result.forensic,
        "protocol": result.protocol_version,
        "cipher": result.cipher_suite,
        "alpn": result.alpn_negotiated,
        "chain_length": result.chain_length,
        "chain_subjects": [subject[:MAX_TEXT] for subject in result.chain_subjects],
        "certificate": {
            "subject_cn": _text(result.subject_cn),
            "issuer_cn": _text(result.issuer_cn),
            "issuer_org": _text(result.issuer_org),
            "sans": [san[:MAX_TEXT] for san in result.sans[:MAX_SANS]],
            "san_count": len(result.sans),
            "wildcard": result.wildcard,
            "not_before": result.not_before.isoformat() if result.not_before else None,
            "not_after": result.not_after.isoformat() if result.not_after else None,
            "days_remaining": result.days_until_expiration,
            "serial": result.serial_number,
            "fingerprint_sha256": result.fingerprint_sha256,
            "key_type": result.key_type,
            "key_bits": result.key_bits,
            "key_curve": result.key_curve,
            "signature_algorithm": result.signature_algorithm,
            "signature_hash": result.signature_hash,
        },
    }
    return CheckOutcome("ok", data=data, source="tls-probe")


class TlsCheck:
    """Probe the TLS endpoint of a host (port 443)."""

    key = "tls"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(self, prober: Prober | None = None) -> None:
        self._prober = prober or probe_tls_endpoint

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        addresses = [str(ip) for ip in dns.data.get("addresses", [])] if dns else []
        if not addresses:
            blocked = dns.data.get("blocked", []) if dns else []
            return CheckOutcome("skipped", "no_public_address", {"blocked": blocked})
        timeout = float(ctx.config.get("EGRESS_CONNECT_TIMEOUT_SEC", 10.0))
        try:
            result = self._prober(
                ctx.hostname or "", PORT, ip_override=addresses[0], timeout=timeout
            )
        except SSRFBlockedError:
            return CheckOutcome("error", "blocked_destination", {"ip": addresses[0]})
        return outcome_from_probe(result)
