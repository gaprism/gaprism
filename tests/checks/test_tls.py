"""Unit and integration tests for live TLS prober and rule evaluation (COL-02)."""

from __future__ import annotations

import datetime
import pathlib
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.service.checks.tls import evaluate_tls_check
from runner.tls import (
    _match_hostname_pattern,
    probe_tls_endpoint,
)


def _generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed root CA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Due Diligence Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return private_key, cert


def _generate_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    sans: list[str],
    not_before: datetime.datetime,
    not_after: datetime.datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a server certificate signed by CA."""
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Target Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    if sans:
        san_list = [x509.DNSName(san) for san in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    return server_key, cert


class EphemeralTLSServer:
    """Ephemeral in-process TLS server for live prober integration tests."""

    def __init__(
        self,
        cert_pem_path: str,
        key_pem_path: str,
    ) -> None:
        self.cert_pem_path = cert_pem_path
        self.key_pem_path = key_pem_path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_pem_path, keyfile=self.key_pem_path)
        self._sock.settimeout(0.5)

        while not self._stop_event.is_set():
            try:
                client_sock, _ = self._sock.accept()
                threading.Thread(
                    target=self._handle_client, args=(context, client_sock), daemon=True
                ).start()
            except TimeoutError:
                continue
            except Exception:
                break

    def _handle_client(self, context: ssl.SSLContext, client_sock: socket.socket) -> None:
        try:
            with context.wrap_socket(client_sock, server_side=True) as ssock:
                _ = ssock.recv(1024)
        except Exception:
            pass

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except Exception:
            pass
        self._thread.join(timeout=1.0)


@pytest.fixture
def test_pki(tmp_path: pathlib.Path) -> dict[str, str]:
    """Create temporary PKI files with CA and various test server certificates."""
    base_dir = tmp_path / "pki"
    base_dir.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _generate_ca()

    ca_pem_path = str(base_dir / "ca.pem")
    with open(ca_pem_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    now = datetime.datetime.now(datetime.UTC)

    # 1. Valid certificate
    valid_key, valid_cert = _generate_server_cert(
        ca_key,
        ca_cert,
        "valid.example.com",
        ["valid.example.com", "sub.valid.example.com", "*.wild.example.com"],
        now - datetime.timedelta(days=10),
        now + datetime.timedelta(days=90),
    )
    valid_cert_path = str(base_dir / "valid_cert.pem")
    valid_key_path = str(base_dir / "valid_key.pem")
    with open(valid_cert_path, "wb") as f:
        f.write(valid_cert.public_bytes(serialization.Encoding.PEM))
    with open(valid_key_path, "wb") as f:
        f.write(
            valid_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    # 2. Expired certificate
    expired_key, expired_cert = _generate_server_cert(
        ca_key,
        ca_cert,
        "expired.example.com",
        ["expired.example.com"],
        now - datetime.timedelta(days=60),
        now - datetime.timedelta(days=10),
    )
    expired_cert_path = str(base_dir / "expired_cert.pem")
    expired_key_path = str(base_dir / "expired_key.pem")
    with open(expired_cert_path, "wb") as f:
        f.write(expired_cert.public_bytes(serialization.Encoding.PEM))
    with open(expired_key_path, "wb") as f:
        f.write(
            expired_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    # 3. Expiring soon certificate (10 days left)
    expiring_key, expiring_cert = _generate_server_cert(
        ca_key,
        ca_cert,
        "expiring.example.com",
        ["expiring.example.com"],
        now - datetime.timedelta(days=80),
        now + datetime.timedelta(days=10),
    )
    expiring_cert_path = str(base_dir / "expiring_cert.pem")
    expiring_key_path = str(base_dir / "expiring_key.pem")
    with open(expiring_cert_path, "wb") as f:
        f.write(expiring_cert.public_bytes(serialization.Encoding.PEM))
    with open(expiring_key_path, "wb") as f:
        f.write(
            expiring_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    return {
        "ca_pem": ca_pem_path,
        "valid_cert": valid_cert_path,
        "valid_key": valid_key_path,
        "expired_cert": expired_cert_path,
        "expired_key": expired_key_path,
        "expiring_cert": expiring_cert_path,
        "expiring_key": expiring_key_path,
    }


class TestHostnamePatternMatching:
    def test_exact_match(self) -> None:
        assert _match_hostname_pattern("example.com", "example.com") is True
        assert _match_hostname_pattern("api.example.com", "api.example.com") is True
        assert _match_hostname_pattern("example.com", "other.com") is False

    def test_wildcard_matching(self) -> None:
        # Standard single level wildcard
        assert _match_hostname_pattern("foo.example.com", "*.example.com") is True
        assert _match_hostname_pattern("bar.example.com", "*.example.com") is True

        # Wildcard does not match root domain
        assert _match_hostname_pattern("example.com", "*.example.com") is False

        # Wildcard does not match multi-level subdomain
        assert _match_hostname_pattern("deep.sub.example.com", "*.example.com") is False


class TestTLSProberLive:
    @pytest.fixture(autouse=True)
    def allow_local_fixture(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("runner.tls.is_ip_public", lambda address: str(address) == "127.0.0.1")

    def test_valid_tls_endpoint(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["valid_cert"], test_pki["valid_key"])
        try:
            res = probe_tls_endpoint(
                hostname="valid.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                custom_ca_file=test_pki["ca_pem"],
            )
            assert res.is_valid is True
            assert res.chain_trust is True
            assert res.hostname_match is True
            assert res.time_valid is True
            assert len(res.failure_reasons) == 0
            assert res.subject_cn == "valid.example.com"
            assert "sub.valid.example.com" in res.sans
            assert res.days_until_expiration is not None and res.days_until_expiration > 30

            # Rule evaluation
            eval_res = evaluate_tls_check(res)
            assert eval_res.status == "succeeded"
            assert eval_res.verdict == "valid"
            assert eval_res.should_skip_http is False
            assert eval_res.skip_reason is None
            assert len(eval_res.findings) == 0
        finally:
            server.close()

    def test_wildcard_san_matching(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["valid_cert"], test_pki["valid_key"])
        try:
            # Matches *.wild.example.com
            res = probe_tls_endpoint(
                hostname="api.wild.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                custom_ca_file=test_pki["ca_pem"],
            )
            assert res.is_valid is True
            assert res.hostname_match is True
        finally:
            server.close()

    def test_col_02_expired_certificate_failure(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["expired_cert"], test_pki["expired_key"])
        try:
            res = probe_tls_endpoint(
                hostname="expired.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                custom_ca_file=test_pki["ca_pem"],
            )
            # Must strictly fail validation (COL-02)
            assert res.is_valid is False
            assert "CERTIFICATE_EXPIRED" in res.failure_reasons

            # Evaluation must emit TLS_VALIDATION_FAILED and halt HTTP checks
            eval_res = evaluate_tls_check(res)
            assert eval_res.status == "failed"
            assert eval_res.verdict == "invalid"
            assert eval_res.should_skip_http is True
            assert eval_res.skip_reason == "skipped_due_to_tls_failure"

            finding = next(f for f in eval_res.findings if f.rule_id == "TLS_VALIDATION_FAILED")
            assert finding.severity == "medium"
            assert finding.confidence == "high"
            assert finding.attribution == "hostname_supported"
        finally:
            server.close()

    def test_col_02_hostname_mismatch(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["valid_cert"], test_pki["valid_key"])
        try:
            res = probe_tls_endpoint(
                hostname="mismatched.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                custom_ca_file=test_pki["ca_pem"],
            )
            assert res.is_valid is False
            assert "HOSTNAME_MISMATCH" in res.failure_reasons

            eval_res = evaluate_tls_check(res)
            assert eval_res.status == "failed"
            assert eval_res.should_skip_http is True
        finally:
            server.close()

    def test_col_02_untrusted_root_ca(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["valid_cert"], test_pki["valid_key"])
        try:
            # Without passing custom_ca_file, self-signed CA is rejected by default root store
            res = probe_tls_endpoint(
                hostname="valid.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                # no custom_ca_file
            )
            assert res.is_valid is False
            assert any(
                "UNTRUSTED_ROOT" in r or "CERTIFICATE_VERIFY_FAILED" in r
                for r in res.failure_reasons
            )

            eval_res = evaluate_tls_check(res)
            assert eval_res.status == "failed"
            assert eval_res.should_skip_http is True
        finally:
            server.close()

    def test_expiring_soon_warning(self, test_pki: dict[str, str]) -> None:
        server = EphemeralTLSServer(test_pki["expiring_cert"], test_pki["expiring_key"])
        try:
            res = probe_tls_endpoint(
                hostname="expiring.example.com",
                port=server.port,
                ip_override="127.0.0.1",
                custom_ca_file=test_pki["ca_pem"],
            )
            assert res.is_valid is True
            assert res.days_until_expiration is not None and res.days_until_expiration <= 30

            eval_res = evaluate_tls_check(res, expiry_warning_days=30)
            assert eval_res.status == "succeeded"
            assert eval_res.verdict == "valid"
            assert eval_res.should_skip_http is False
            assert eval_res.skip_reason is None

            finding = next(f for f in eval_res.findings if f.rule_id == "TLS_EXPIRING_SOON")
            assert finding.severity == "low"
            assert finding.confidence == "high"
            assert finding.attribution == "hostname_supported"
            assert finding.message_parameters["days_remaining"] == res.days_until_expiration
        finally:
            server.close()

    def test_connection_refused_handling(self) -> None:
        # Probe an unused port
        res = probe_tls_endpoint(
            hostname="localhost",
            port=59999,
            ip_override="127.0.0.1",
            timeout=1.0,
        )
        assert res.is_valid is False
        assert any(
            "CONNECTION_REFUSED" in r or "CONNECTION_FAILED" in r or "TIMEOUT" in r
            for r in res.failure_reasons
        )

        eval_res = evaluate_tls_check(res)
        assert eval_res.status == "failed"
        assert eval_res.should_skip_http is True
