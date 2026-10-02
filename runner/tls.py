"""Live TLS endpoint prober with trust verification, SAN checks, and failure classification."""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class TLSProbeResult:
    """Immutable result of probing an endpoint's TLS configuration."""

    hostname: str
    port: int
    connected_ip: str | None
    is_valid: bool
    chain_trust: bool
    hostname_match: bool
    time_valid: bool
    failure_reasons: list[str] = field(default_factory=list)
    not_before: datetime.datetime | None = None
    not_after: datetime.datetime | None = None
    days_until_expiration: int | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None
    issuer_org: str | None = None
    sans: list[str] = field(default_factory=list)
    serial_number: str | None = None
    fingerprint_sha256: str | None = None
    cipher_suite: str | None = None
    protocol_version: str | None = None
    alpn_negotiated: str | None = None
    collected_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to serialisable dictionary."""
        return {
            "hostname": self.hostname,
            "port": self.port,
            "connected_ip": self.connected_ip,
            "is_valid": self.is_valid,
            "chain_trust": self.chain_trust,
            "hostname_match": self.hostname_match,
            "time_valid": self.time_valid,
            "failure_reasons": self.failure_reasons,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_until_expiration": self.days_until_expiration,
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "sans": self.sans,
            "serial_number": self.serial_number,
            "fingerprint_sha256": self.fingerprint_sha256,
            "cipher_suite": self.cipher_suite,
            "protocol_version": self.protocol_version,
            "alpn_negotiated": self.alpn_negotiated,
            "collected_at": self.collected_at.isoformat(),
        }


def _match_hostname_pattern(hostname: str, pattern: str) -> bool:
    """Check if a hostname matches a certificate SAN pattern (including RFC 6125 wildcards)."""
    h = hostname.lower().strip(".")
    p = pattern.lower().strip(".")

    if h == p:
        return True

    if p.startswith("*."):
        # Wildcard only matches a single subdomain level (e.g. *.example.com matches
        # foo.example.com, not foo.bar.example.com)
        suffix = p[2:]
        if "." not in suffix:
            return False
        if h.endswith(f".{suffix}"):
            prefix = h[: -(len(suffix) + 1)]
            return bool(prefix and "." not in prefix)

    return False


def _parse_cert_metadata(der_bytes: bytes) -> dict[str, Any]:
    """Parse X.509 certificate metadata from binary DER representation."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    except Exception:
        return {}

    subject_cn = None
    for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        subject_cn = attr.value if isinstance(attr.value, str) else attr.value.decode("utf-8")

    issuer_cn = None
    for attr in cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        issuer_cn = attr.value if isinstance(attr.value, str) else attr.value.decode("utf-8")

    issuer_org = None
    for attr in cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME):
        issuer_org = attr.value if isinstance(attr.value, str) else attr.value.decode("utf-8")

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_value = san_ext.value
        if isinstance(san_value, x509.SubjectAlternativeName):
            for name in san_value:
                if isinstance(name, x509.DNSName):
                    sans.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Ensure UTC timezone aware datetimes
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    now = datetime.datetime.now(datetime.UTC)
    days_left = (not_after - now).days

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = hex(cert.serial_number)[2:].upper()

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiration": days_left,
        "fingerprint_sha256": fingerprint,
        "serial_number": serial,
    }


def probe_tls_endpoint(
    hostname: str,
    port: int = 443,
    ip_override: str | None = None,
    timeout: float = 10.0,
    custom_ca_file: str | None = None,
) -> TLSProbeResult:
    """Probe an HTTPS endpoint's live TLS certificate and configuration.

    Enforces:
    - Root CA trust validation against the standard root store (or custom_ca_file if specified).
    - SAN and Common Name matching against the target hostname.
    - Certificate validity dates (not before / not after).
    - Explicit classification of failure reasons.
    - NEVER falls back to verify=False as valid (INV-05, COL-02).
    """
    target_host = hostname.strip().lower()
    connect_host = ip_override if ip_override else target_host

    # 1. First attempt: Strict verification context
    verified_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if custom_ca_file:
        verified_context.load_verify_locations(cafile=custom_ca_file)
    # Enable ALPN negotiation for HTTP/2 and HTTP/1.1
    try:
        verified_context.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    chain_trust = False
    hostname_match = False
    time_valid = False
    failure_reasons: list[str] = []
    connected_ip: str | None = ip_override
    der_cert: bytes | None = None
    cipher_suite: str | None = None
    protocol_version: str | None = None
    alpn_negotiated: str | None = None

    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            peer_name = sock.getpeername()
            if isinstance(peer_name, tuple) and len(peer_name) >= 1:
                connected_ip = str(peer_name[0])

            with verified_context.wrap_socket(sock, server_hostname=target_host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_suite = cipher_info[0]
                protocol_version = ssock.version()
                alpn_negotiated = ssock.selected_alpn_protocol()
                chain_trust = True
                hostname_match = True
                time_valid = True

    except ssl.SSLCertVerificationError as e:
        # Explicit certificate verification failure
        error_msg = str(e)
        if "certificate has expired" in error_msg.lower():
            failure_reasons.append("CERTIFICATE_EXPIRED")
        elif "certificate is not yet valid" in error_msg.lower():
            failure_reasons.append("CERTIFICATE_NOT_YET_VALID")
        elif (
            "hostname" in error_msg.lower()
            or "ip address mismatch" in error_msg.lower()
            or "doesn't match" in error_msg.lower()
        ):
            failure_reasons.append("HOSTNAME_MISMATCH")
        elif (
            "self-signed" in error_msg.lower()
            or "self signed" in error_msg.lower()
            or "unable to get local issuer certificate" in error_msg.lower()
            or "certificate verify failed" in error_msg.lower()
        ):
            failure_reasons.append("UNTRUSTED_ROOT")
        else:
            failure_reasons.append(f"CERTIFICATE_VERIFY_FAILED: {e.verify_message or error_msg}")

    except ssl.SSLError as e:
        failure_reasons.append(f"TLS_HANDSHAKE_FAILED: {e}")

    except TimeoutError:
        failure_reasons.append("TIMEOUT")

    except ConnectionRefusedError:
        failure_reasons.append("CONNECTION_REFUSED")

    except OSError as e:
        failure_reasons.append(f"CONNECTION_FAILED: {e}")

    # 2. If verification failed but connection was possible, retrieve unverified
    # certificate metadata for forensic facts
    if der_cert is None and (
        "CERTIFICATE_" in str(failure_reasons)
        or "UNTRUSTED_ROOT" in str(failure_reasons)
        or "HOSTNAME_MISMATCH" in str(failure_reasons)
        or "TLS_HANDSHAKE_FAILED" in str(failure_reasons)
    ):
        try:
            unverified_context = ssl._create_unverified_context()
            with socket.create_connection((connect_host, port), timeout=timeout) as unverified_sock:
                peer_name = unverified_sock.getpeername()
                if isinstance(peer_name, tuple) and len(peer_name) >= 1:
                    connected_ip = str(peer_name[0])
                with unverified_context.wrap_socket(
                    unverified_sock, server_hostname=target_host
                ) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_suite = cipher_info[0]
                    protocol_version = ssock.version()
                    alpn_negotiated = ssock.selected_alpn_protocol()
        except Exception:
            pass

    # 3. Parse certificate metadata if available
    cert_meta: dict[str, Any] = {}
    if der_cert:
        cert_meta = _parse_cert_metadata(der_cert)
        # Perform explicit granular checks if unverified context was used
        if not chain_trust:
            now = datetime.datetime.now(datetime.UTC)
            nb = cert_meta.get("not_before")
            na = cert_meta.get("not_after")
            if nb and na:
                if nb <= now <= na:
                    time_valid = True
                else:
                    time_valid = False
                    if now < nb and "CERTIFICATE_NOT_YET_VALID" not in failure_reasons:
                        failure_reasons.append("CERTIFICATE_NOT_YET_VALID")
                    if now > na and "CERTIFICATE_EXPIRED" not in failure_reasons:
                        failure_reasons.append("CERTIFICATE_EXPIRED")

            sans = cert_meta.get("sans", [])
            subject_cn = cert_meta.get("subject_cn")
            names_to_check = list(sans)
            if subject_cn and subject_cn not in names_to_check:
                names_to_check.append(subject_cn)

            matched = any(_match_hostname_pattern(target_host, name) for name in names_to_check)
            if matched:
                hostname_match = True
            else:
                hostname_match = False
                if "HOSTNAME_MISMATCH" not in failure_reasons:
                    failure_reasons.append("HOSTNAME_MISMATCH")

    is_valid = bool(chain_trust and hostname_match and time_valid and not failure_reasons)

    return TLSProbeResult(
        hostname=target_host,
        port=port,
        connected_ip=connected_ip,
        is_valid=is_valid,
        chain_trust=chain_trust,
        hostname_match=hostname_match,
        time_valid=time_valid,
        failure_reasons=failure_reasons,
        not_before=cert_meta.get("not_before"),
        not_after=cert_meta.get("not_after"),
        days_until_expiration=cert_meta.get("days_until_expiration"),
        subject_cn=cert_meta.get("subject_cn"),
        issuer_cn=cert_meta.get("issuer_cn"),
        issuer_org=cert_meta.get("issuer_org"),
        sans=cert_meta.get("sans", []),
        serial_number=cert_meta.get("serial_number"),
        fingerprint_sha256=cert_meta.get("fingerprint_sha256"),
        cipher_suite=cipher_suite,
        protocol_version=protocol_version,
        alpn_negotiated=alpn_negotiated,
    )
