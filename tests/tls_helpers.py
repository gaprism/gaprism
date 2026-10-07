"""Certificates and a throw-away local TLS server for testing the TLS prober (no network).

Python's default context verifies strictly (RFC 5280 rules), so generated certificates carry the
extensions a real CA would add: key identifiers, key usage and basic constraints.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAY = datetime.timedelta(days=1)


@dataclass
class Issued:
    key: Any
    cert: x509.Certificate

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


def _key(kind: str, bits: int = 2048) -> Any:
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def issue(
    subject_cn: str,
    *,
    sans: list[str] | None = None,
    issuer: Issued | None = None,
    ca: bool = False,
    key_kind: str = "rsa",
    key_bits: int = 2048,
    starts: datetime.timedelta = -DAY,
    ends: datetime.timedelta = 30 * DAY,
    digest: hashes.HashAlgorithm | None = None,
    serial: int | None = None,
) -> Issued:
    """A certificate for ``subject_cn``; self-signed unless ``issuer`` is given."""
    key = _key(key_kind, key_bits)
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.cert.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number() if serial is None else serial)
        .not_valid_before(now + starts)
        .not_valid_after(now + ends)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()),
            critical=False,
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]), critical=False
        )
    signer = issuer.key if issuer else key
    return Issued(key, builder.sign(signer, digest or hashes.SHA256()))


def der_with_serial_byte(issued: Issued, value: int) -> bytes:
    """The DER of a certificate made with ``issue(..., serial=5)``, its serial number overwritten
    by the single byte ``value``: 0x00 is zero, 0xFB is -5. This is how a faulty authority's
    certificate looks. The signature no longer matches, which parsing does not check, and the
    encoding stays minimal (a one-byte INTEGER), so strict parsers still accept the structure."""
    der = issued.der
    marker = bytes.fromhex("a003020102020105")  # [0] version v3, then INTEGER 5
    assert der.count(marker) == 1, "build the certificate with serial=5"
    return der.replace(marker, marker[:-1] + bytes([value]))


def write_pem(directory: Path, name: str, leaf: Issued, *chain: Issued) -> tuple[str, str]:
    """Write ``leaf`` (followed by ``chain``) and its key; returns (certificate file, key file)."""
    certfile = directory / f"{name}.pem"
    keyfile = directory / f"{name}.key"
    certfile.write_bytes(
        b"".join(item.cert.public_bytes(serialization.Encoding.PEM) for item in (leaf, *chain))
    )
    keyfile.write_bytes(
        leaf.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile)


def write_ca(directory: Path, name: str, ca: Issued) -> str:
    """Write a CA certificate as a trust file for ``custom_ca_file``."""
    path = directory / f"{name}.pem"
    path.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


class TlsServer:
    """A local endpoint on 127.0.0.1.

    ``tls``: completes handshakes with the given certificate · ``plain``: answers every
    connection with a plain HTTP error (not TLS at all) · ``silent``: accepts and never speaks.
    """

    def __init__(self, mode: str = "tls", certfile: str = "", keyfile: str = "") -> None:
        self.mode = mode
        self.context: ssl.SSLContext | None = None
        if mode == "tls":
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(certfile, keyfile)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port: int = self.listener.getsockname()[1]
        self._held: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return  # the listener was closed
            try:
                if self.mode == "tls" and self.context is not None:
                    with self.context.wrap_socket(connection, server_side=True) as secured:
                        secured.settimeout(2)
                        secured.recv(1)  # returns when the prober hangs up
                elif self.mode == "plain":
                    connection.settimeout(2)
                    connection.recv(4096)  # the ClientHello; answering unread data would reset
                    connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    connection.shutdown(socket.SHUT_WR)
                    connection.close()
                else:
                    self._held.append(connection)
            except (OSError, ssl.SSLError):
                connection.close()

    def close(self) -> None:
        self.listener.close()
        for held in self._held:
            held.close()

    def __enter__(self) -> TlsServer:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def closed_port() -> int:
    """A port on 127.0.0.1 that nothing listens on (just released)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
