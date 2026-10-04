"""The TLS prober against a throw-away local server: facts, failures and the forensic read."""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest

from runner.dns import SSRFBlockedError
from runner.tls import (
    TLSProbeResult,
    _parse_cert_metadata,
    _signature_details,
    probe_tls_endpoint,
)
from tests.tls_helpers import (
    DAY,
    Issued,
    TlsServer,
    closed_port,
    issue,
    write_ca,
    write_pem,
)

HOST = "test.example.com"
LOOPBACK = "127.0.0.1"


@pytest.fixture
def allow_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate refuses loopback by design; the local test server needs it opened (tests only)."""
    monkeypatch.setattr("runner.tls.is_ip_public", lambda ip: True)


@pytest.fixture(scope="module")
def ca() -> Issued:
    return issue("Test Root CA", ca=True, key_kind="ec")


@pytest.fixture(scope="module")
def rsa_ca() -> Issued:
    return issue("Test RSA Root CA", ca=True)


@pytest.fixture
def trust(tmp_path: Path, ca: Issued) -> str:
    return write_ca(tmp_path, "ca", ca)


def serve(tmp_path: Path, leaf: Issued, *chain: Issued) -> TlsServer:
    certfile, keyfile = write_pem(tmp_path, "server", leaf, *chain)
    return TlsServer("tls", certfile, keyfile)


def probe(server: TlsServer, trust_file: str | None = None, host: str = HOST) -> TLSProbeResult:
    return probe_tls_endpoint(
        host, server.port, ip_override=LOOPBACK, timeout=5, custom_ca_file=trust_file
    )


# ------------------------------------------------------------------------------ a good certificate


def test_a_trusted_certificate_reports_its_facts(
    allow_loopback: None, tmp_path: Path, rsa_ca: Issued
) -> None:
    leaf = issue(HOST, sans=[HOST, "www.test.example.com"], issuer=rsa_ca)
    with serve(tmp_path, leaf) as server:
        result = probe(server, write_ca(tmp_path, "rsa-ca", rsa_ca))

    assert result.is_valid and result.chain_trust and result.hostname_match and result.time_valid
    assert result.failure_reasons == [] and result.forensic is False
    assert (result.key_type, result.key_bits, result.key_curve) == ("RSA", 2048, None)
    assert (result.signature_algorithm, result.signature_hash) == (
        "sha256WithRSAEncryption",
        "sha256",
    )
    assert result.wildcard is False and result.sans == [HOST, "www.test.example.com"]
    assert result.protocol_version is not None and result.protocol_version.startswith("TLSv1.")
    assert result.cipher_suite and result.issuer_cn == "Test RSA Root CA"
    assert result.days_until_expiration in (29, 30)
    assert result.connected_ip == LOOPBACK
    if hasattr(ssl.SSLSocket, "get_verified_chain"):  # Python 3.13+
        assert result.chain_length == 2  # the leaf and the trusted root
        assert result.chain_subjects[0] == f"CN={HOST}"


def test_an_elliptic_curve_certificate_reports_curve_and_bits(
    allow_loopback: None, tmp_path: Path, ca: Issued, trust: str
) -> None:
    with serve(tmp_path, issue(HOST, sans=[HOST], issuer=ca, key_kind="ec")) as server:
        result = probe(server, trust)
    assert result.is_valid
    assert (result.key_type, result.key_bits, result.key_curve) == ("EC", 256, "secp256r1")
    assert result.signature_algorithm == "ecdsa-with-SHA256" or result.signature_hash == "sha256"


def test_a_wildcard_certificate_is_flagged(
    allow_loopback: None, tmp_path: Path, ca: Issued, trust: str
) -> None:
    with serve(tmp_path, issue("*.example.com", sans=["*.example.com"], issuer=ca)) as server:
        result = probe(server, trust)
    assert result.is_valid and result.wildcard is True


# ------------------------------------------------------------------------------ bad certificates


def test_an_expired_certificate_is_read_forensically_and_never_valid(
    allow_loopback: None, tmp_path: Path, ca: Issued, trust: str
) -> None:
    expired = issue(HOST, sans=[HOST], issuer=ca, starts=-60 * DAY, ends=-1 * DAY)
    with serve(tmp_path, expired) as server:
        result = probe(server, trust)

    assert result.is_valid is False and result.chain_trust is False
    assert "CERTIFICATE_EXPIRED" in result.failure_reasons
    assert result.forensic is True  # the facts came from the labelled, unverified connection
    assert result.fingerprint_sha256 and result.days_until_expiration is not None
    assert result.days_until_expiration < 0
    assert result.key_type == "RSA" and result.sans == [HOST]


def test_a_certificate_for_another_name_is_a_hostname_mismatch(
    allow_loopback: None, tmp_path: Path, ca: Issued, trust: str
) -> None:
    with serve(
        tmp_path, issue("other.example.org", sans=["other.example.org"], issuer=ca)
    ) as server:
        result = probe(server, trust)
    assert result.is_valid is False and result.hostname_match is False
    assert result.failure_reasons == ["HOSTNAME_MISMATCH"]
    assert result.forensic is True and result.sans == ["other.example.org"]


def test_an_issuer_we_do_not_trust_is_reported_as_untrusted_root(
    allow_loopback: None, tmp_path: Path, ca: Issued
) -> None:
    with serve(tmp_path, issue(HOST, sans=[HOST], issuer=ca)) as server:
        result = probe(server, trust_file=None)  # the test CA is not in the system store
    assert result.is_valid is False and result.chain_trust is False
    assert "UNTRUSTED_ROOT" in result.failure_reasons
    assert result.forensic is True and result.hostname_match is True


def test_a_self_signed_certificate_is_untrusted(allow_loopback: None, tmp_path: Path) -> None:
    with serve(tmp_path, issue(HOST, sans=[HOST])) as server:
        result = probe(server)
    assert result.is_valid is False and "UNTRUSTED_ROOT" in result.failure_reasons
    assert result.issuer_cn == HOST  # issued by itself


def test_a_short_key_is_visible_in_the_parsed_certificate() -> None:
    meta = _parse_cert_metadata(issue(HOST, sans=[HOST], key_bits=1024).der)  # parse only
    assert (meta["key_type"], meta["key_bits"]) == ("RSA", 1024)


@pytest.mark.parametrize(
    ("oid", "digest", "expected"),
    [
        ("1.2.840.113549.1.1.5", "sha1", ("sha1WithRSAEncryption", "sha1")),  # weak
        ("1.2.840.113549.1.1.4", "md5", ("md5WithRSAEncryption", "md5")),  # weak
        ("1.2.840.10045.4.3.3", "sha384", ("ecdsa-with-SHA384", "sha384")),
        ("1.3.101.112", None, ("Ed25519", None)),  # no separate hash
        ("1.2.3.4.5", "sha256", ("1.2.3.4.5", "sha256")),  # unknown: the OID itself
    ],
)
def test_signature_algorithms_are_named_or_left_as_their_oid(
    oid: str, digest: str | None, expected: tuple[str, str | None]
) -> None:
    # cryptography refuses to *create* SHA-1/MD5 signatures, so these certificates are stand-ins.
    certificate = SimpleNamespace(
        signature_algorithm_oid=SimpleNamespace(dotted_string=oid),
        signature_hash_algorithm=SimpleNamespace(name=digest) if digest else None,
    )
    assert _signature_details(certificate) == expected  # type: ignore[arg-type]


def test_the_common_name_counts_for_a_wildcard_only_without_sans() -> None:
    only_cn = _parse_cert_metadata(issue("*.example.com").der)
    with_sans = _parse_cert_metadata(issue("*.example.com", sans=["www.example.com"]).der)
    assert only_cn["wildcard"] is True and with_sans["wildcard"] is False


# ------------------------------------------------------------------------------ no certificate


def test_a_port_with_no_listener_is_refused(allow_loopback: None) -> None:
    result = probe_tls_endpoint(HOST, closed_port(), ip_override=LOOPBACK, timeout=5)
    assert result.failure_reasons == ["CONNECTION_REFUSED"]
    assert result.fingerprint_sha256 is None and result.forensic is False


def test_a_server_that_never_answers_times_out(allow_loopback: None) -> None:
    with TlsServer("silent") as server:
        result = probe_tls_endpoint(HOST, server.port, ip_override=LOOPBACK, timeout=0.5)
    assert result.failure_reasons == ["TIMEOUT"]
    assert result.fingerprint_sha256 is None


def test_plain_http_on_the_tls_port_fails_the_handshake(allow_loopback: None) -> None:
    with TlsServer("plain") as server:
        result = probe_tls_endpoint(HOST, server.port, ip_override=LOOPBACK, timeout=5)
    assert any(reason.startswith("TLS_HANDSHAKE_FAILED") for reason in result.failure_reasons)
    assert result.fingerprint_sha256 is None and result.is_valid is False


# ------------------------------------------------------------------------------ the gate


def test_the_gate_still_refuses_loopback_without_the_test_override() -> None:
    with pytest.raises(SSRFBlockedError):
        probe_tls_endpoint(HOST, 443, ip_override=LOOPBACK, timeout=1)
    with pytest.raises(SSRFBlockedError):
        probe_tls_endpoint(HOST, 443, ip_override="10.0.0.1", timeout=1)


def test_the_result_serialises_with_the_new_facts(
    allow_loopback: None, tmp_path: Path, ca: Issued, trust: str
) -> None:
    with serve(tmp_path, issue(HOST, sans=[HOST], issuer=ca)) as server:
        data = probe(server, trust).to_dict()
    for key in (
        "key_type",
        "key_bits",
        "key_curve",
        "signature_algorithm",
        "signature_hash",
        "wildcard",
        "chain_length",
        "chain_subjects",
        "forensic",
    ):
        assert key in data
    assert datetime.datetime.fromisoformat(data["not_after"]) > datetime.datetime.now(datetime.UTC)
