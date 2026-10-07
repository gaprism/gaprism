"""Live TLS endpoint prober with trust verification, SAN checks, and failure classification."""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import socket
import ssl
import threading
import warnings
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning

from runner.dns import SSRFBlockedError, is_ip_public, resolve_and_screen

# Names for the signature algorithm OIDs that matter for a due-diligence reader (weak ones
# included); anything else is reported by its dotted OID.
_SIGNATURE_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
MAX_CHAIN_CERTIFICATES = 10
MAX_NAME_LENGTH = 200

# ``cryptography`` warns (when a certificate is loaded and each time its serial number is read)
# that a future release will refuse a certificate whose serial number is zero or negative: RFC 5280
# requires a positive one, but a few old authorities issued others, and this prober reads whatever
# other people's servers present. The fact is part of the result (``serial_positive``) where an
# analyst can see which host it is, so the warning is silenced where certificates are read.
# ``catch_warnings`` changes process-wide state: one thread at a time.
_SERIAL_WARNING = "Parsed a serial number which wasn't positive"
_WARNING_LOCK = threading.Lock()


@contextlib.contextmanager
def _serial_warning_silenced() -> Iterator[None]:
    with _WARNING_LOCK, warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", message=_SERIAL_WARNING, category=CryptographyDeprecationWarning
        )
        yield


def _load_certificate(der: bytes) -> x509.Certificate:
    """Parse a DER certificate; ``ValueError`` if it cannot be read."""
    with _serial_warning_silenced():
        return x509.load_der_x509_certificate(der, default_backend())


def _serial_of(cert: x509.Certificate) -> int:
    with _serial_warning_silenced():
        return cert.serial_number


def _serial_text(serial: int) -> str:
    """The serial number in hex, with a minus sign if it is negative (it should not be)."""
    return ("-" if serial < 0 else "") + format(abs(serial), "X")


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
    serial_positive: bool | None = None  # False: zero or negative, which RFC 5280 forbids
    fingerprint_sha256: str | None = None
    cipher_suite: str | None = None
    protocol_version: str | None = None
    alpn_negotiated: str | None = None
    key_type: str | None = None  # RSA, EC, Ed25519, Ed448, DSA
    key_bits: int | None = None
    key_curve: str | None = None  # EC only, e.g. secp256r1
    signature_algorithm: str | None = None  # e.g. sha256WithRSAEncryption
    signature_hash: str | None = None  # e.g. sha256 (None for Ed25519/Ed448)
    wildcard: bool = False  # a SAN or the CN is a "*." pattern
    chain_length: int | None = None  # None when this Python cannot expose the chain
    chain_subjects: list[str] = field(default_factory=list)
    # True when the certificate facts were read after verification had failed, through a
    # separate connection whose certificate is NOT trusted. ``is_valid`` is False then.
    forensic: bool = False
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
            "serial_positive": self.serial_positive,
            "fingerprint_sha256": self.fingerprint_sha256,
            "cipher_suite": self.cipher_suite,
            "protocol_version": self.protocol_version,
            "alpn_negotiated": self.alpn_negotiated,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "key_curve": self.key_curve,
            "signature_algorithm": self.signature_algorithm,
            "signature_hash": self.signature_hash,
            "wildcard": self.wildcard,
            "chain_length": self.chain_length,
            "chain_subjects": self.chain_subjects,
            "forensic": self.forensic,
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


def _key_details(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    """Key family, size in bits and (for EC) the curve name of the certificate's public key."""
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return None, None, None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    return type(key).__name__, None, None


def _signature_details(cert: x509.Certificate) -> tuple[str, str | None]:
    """The signature algorithm (named when it is a common one) and its hash, if it has one."""
    oid = cert.signature_algorithm_oid.dotted_string
    try:
        digest = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        digest = None
    return _SIGNATURE_NAMES.get(oid, oid), digest.name if digest is not None else None


def _chain_facts(ssock: ssl.SSLSocket, verified: bool) -> tuple[int | None, list[str]]:
    """How many certificates the peer's chain has and who they belong to.

    ``SSLSocket.get_verified_chain`` / ``get_unverified_chain`` exist from Python 3.13; on older
    versions the chain is simply not reported (``None``), never guessed.
    """
    getter = getattr(ssock, "get_verified_chain" if verified else "get_unverified_chain", None)
    if getter is None:
        return None, []
    try:
        chain = list(getter())
    except (ValueError, OSError, ssl.SSLError):
        return None, []
    subjects: list[str] = []
    for der in chain[:MAX_CHAIN_CERTIFICATES]:  # DER bytes, one per certificate
        try:
            cert = _load_certificate(bytes(der))
        except ValueError:
            subjects.append("(unreadable)")
            continue
        subjects.append(cert.subject.rfc4514_string()[:MAX_NAME_LENGTH])
    return len(chain), subjects


def _parse_cert_metadata(der_bytes: bytes) -> dict[str, Any]:
    """Parse X.509 certificate metadata from binary DER representation.

    A certificate that was received but cannot be read comes back as ``{"unreadable": True}``:
    something was presented, so it must never look like "no certificate".
    """
    try:
        cert = _load_certificate(der_bytes)
    except Exception:
        return {"unreadable": True}

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
    serial_number = _serial_of(cert)
    key_type, key_bits, key_curve = _key_details(cert)
    signature_algorithm, signature_hash = _signature_details(cert)
    # Browsers ignore the CN when SANs exist, so it only counts when there are none.
    wildcard = any(name.startswith("*.") for name in (sans or [subject_cn or ""]))

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiration": days_left,
        "fingerprint_sha256": fingerprint,
        "serial_number": _serial_text(serial_number),
        "serial_positive": serial_number > 0,
        "key_type": key_type,
        "key_bits": key_bits,
        "key_curve": key_curve,
        "signature_algorithm": signature_algorithm,
        "signature_hash": signature_hash,
        "wildcard": wildcard,
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
    # Resolve exactly once and connect only to the screened numeric address.
    if ip_override is not None:
        try:
            candidate = ipaddress.ip_address(ip_override)
        except ValueError as exc:
            raise SSRFBlockedError("TLS destination must be a numeric public IP.") from exc
        if not is_ip_public(candidate):
            raise SSRFBlockedError("TLS destination is not a public IP.")
        connect_host = str(candidate)
    else:
        connect_host = str(resolve_and_screen(target_host)[0])
    if not 1 <= port <= 65535 or not 0 < timeout <= 30:
        raise ValueError("Invalid TLS port or timeout.")

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
    chain_length: int | None = None
    chain_subjects: list[str] = []
    forensic = False

    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(connect_host):
                raise SSRFBlockedError("TLS connection peer differs from screened IP.")
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
                chain_length, chain_subjects = _chain_facts(ssock, verified=True)
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
        # Best effort: the verified attempt already failed, so network and TLS errors here only
        # mean that no forensic metadata is available. SSRF violations still propagate.
        with contextlib.suppress(OSError):
            # Reads certificate facts only; nothing is sent and nothing from this connection is
            # trusted (hence no verification). `is_valid` stays False.
            unverified_context = ssl._create_unverified_context()  # noqa: S323
            with socket.create_connection((connect_host, port), timeout=timeout) as unverified_sock:
                if ipaddress.ip_address(unverified_sock.getpeername()[0]) != ipaddress.ip_address(
                    connect_host
                ):
                    raise SSRFBlockedError("TLS metadata connection peer differs from screened IP.")
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
                    chain_length, chain_subjects = _chain_facts(ssock, verified=False)
                    forensic = der_cert is not None

    # 3. Parse certificate metadata if available
    cert_meta: dict[str, Any] = {}
    if der_cert:
        cert_meta = _parse_cert_metadata(der_cert)
        if cert_meta.get("unreadable"):
            # Never "valid", and never "no certificate": one was presented and could not be read.
            failure_reasons.append("CERTIFICATE_UNREADABLE")
        # Perform explicit granular checks if unverified context was used
        elif not chain_trust:
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
        serial_positive=cert_meta.get("serial_positive"),
        fingerprint_sha256=cert_meta.get("fingerprint_sha256"),
        cipher_suite=cipher_suite,
        protocol_version=protocol_version,
        alpn_negotiated=alpn_negotiated,
        key_type=cert_meta.get("key_type"),
        key_bits=cert_meta.get("key_bits"),
        key_curve=cert_meta.get("key_curve"),
        signature_algorithm=cert_meta.get("signature_algorithm"),
        signature_hash=cert_meta.get("signature_hash"),
        wildcard=bool(cert_meta.get("wildcard", False)),
        chain_length=chain_length,
        chain_subjects=chain_subjects,
        forensic=forensic,
    )
