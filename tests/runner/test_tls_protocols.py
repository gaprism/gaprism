"""The protocol prober against throw-away local servers that speak only what they are told to."""

from __future__ import annotations

import socket
import ssl
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from runner.dns import SSRFBlockedError
from runner.tls_protocols import (
    LEGACY_SUITES,
    NOT_TESTED,
    SUITE_KINDS,
    VERSIONS,
    Attempt,
    TLSProtocolsResult,
    _classify,
    _context,
    forward_secret,
    probe_tls_protocols,
)
from tests.tls_helpers import TlsServer, closed_port, issue, write_pem

HOST = "test.example.com"
LOOPBACK = "127.0.0.1"
V = ssl.TLSVersion
ALL_SUITES = "ALL:@SECLEVEL=0"


@pytest.fixture(autouse=True)
def allow_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate refuses loopback by design; the local test servers need it opened (tests only)."""
    monkeypatch.setattr("runner.tls_protocols.is_ip_public", lambda ip: True)


def can_offer(version: str) -> bool:
    try:
        _context(version, version, None if version == "TLSv1.3" else LEGACY_SUITES)
    except (ValueError, ssl.SSLError):
        return False
    return True


needs_legacy = pytest.mark.skipif(
    not (can_offer("TLSv1") and can_offer("TLSv1.1")),
    reason="this OpenSSL cannot offer TLS 1.0 and 1.1",
)


@pytest.fixture
def serve(tmp_path: Path) -> Iterator[Callable[..., TlsServer]]:
    servers: list[TlsServer] = []
    certfile, keyfile = write_pem(tmp_path, "server", issue(HOST, sans=[HOST]))

    def start(
        versions: tuple[ssl.TLSVersion, ssl.TLSVersion], ciphers: str | None = ALL_SUITES
    ) -> TlsServer:
        server = TlsServer("tls", certfile, keyfile, versions=versions, ciphers=ciphers)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def probe(port: int, **kwargs: object) -> TLSProtocolsResult:
    return probe_tls_protocols(HOST, port, ip_override=LOOPBACK, timeout=3, **kwargs)  # type: ignore[arg-type]


def statuses(result: TLSProtocolsResult) -> dict[str, str]:
    return {attempt.key: attempt.status for attempt in result.attempts}


# ------------------------------------------------------------------------------ versions


def test_a_modern_server_accepts_the_modern_versions_and_refuses_the_old(
    serve: Callable[..., TlsServer],
) -> None:
    result = probe(serve((V.TLSv1_2, V.TLSv1_3), "ECDHE+AESGCM").port)
    assert statuses(result) == {
        "TLSv1.2": "accepted",
        "TLSv1.3": "accepted",
        "TLSv1.1": "rejected",
        "TLSv1": "rejected",
        "anonymous_or_null": "rejected",
    }
    assert result.reachable and result.accepted() == ["TLSv1.2", "TLSv1.3"]
    accepted = {a.key: a for a in result.versions if a.status == "accepted"}
    assert accepted["TLSv1.2"].version == "TLSv1.2" and accepted["TLSv1.2"].cipher
    tls13 = accepted["TLSv1.3"]
    assert (
        tls13.version == "TLSv1.3" and tls13.cipher is not None and tls13.cipher.startswith("TLS_")
    )
    assert {a.reason for a in result.attempts if a.status == "rejected"} == {"alert"}


def test_a_tls_1_2_server_does_not_accept_tls_1_3(serve: Callable[..., TlsServer]) -> None:
    result = probe(serve((V.TLSv1_2, V.TLSv1_2), "DEFAULT").port)
    assert result.accepted() == ["TLSv1.2"]
    assert statuses(result)["TLSv1.3"] == "rejected"


def test_a_tls_1_3_only_server_is_asked_the_other_versions_too(
    serve: Callable[..., TlsServer],
) -> None:
    result = probe(serve((V.TLSv1_3, V.TLSv1_3), None).port)
    assert result.accepted() == ["TLSv1.3"] and result.reachable
    assert {a.status for a in result.versions if a.key != "TLSv1.3"} == {"rejected"}
    assert {a.status for a in result.suites} == {"rejected"}  # no suite at 1.0 to 1.2
    assert [a.key for a in result.suites] == list(SUITE_KINDS)


@needs_legacy
def test_a_server_that_still_speaks_the_deprecated_versions_is_found_out(
    serve: Callable[..., TlsServer],
) -> None:
    result = probe(serve((V.TLSv1, V.TLSv1_3), ALL_SUITES).port)
    assert result.accepted() == ["TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1"]  # in the order asked
    old = {a.key: a for a in result.versions}
    assert old["TLSv1"].version == "TLSv1" and old["TLSv1.1"].version == "TLSv1.1"


@needs_legacy
def test_a_server_that_speaks_only_a_deprecated_version_is_still_reachable(
    serve: Callable[..., TlsServer],
) -> None:
    """The control is any accepted handshake, not a modern one: this is the worst case to see."""
    result = probe(serve((V.TLSv1, V.TLSv1), ALL_SUITES).port)
    assert result.accepted() == ["TLSv1"] and result.reachable
    assert statuses(result)["TLSv1.2"] == "rejected" and statuses(result)["TLSv1.3"] == "rejected"


# ------------------------------------------------------------------------------ kinds of suites


def test_the_suite_a_server_chooses_shows_whether_it_prefers_forward_secrecy(
    serve: Callable[..., TlsServer],
) -> None:
    """The TLS 1.2 handshake offers both kinds; what the server picks is its own preference."""
    modern = probe(serve((V.TLSv1_2, V.TLSv1_2), "ECDHE+AESGCM").port)
    chosen = {a.key: a.cipher for a in modern.versions}["TLSv1.2"]
    assert chosen is not None and forward_secret(chosen)
    rsa_only = probe(serve((V.TLSv1_2, V.TLSv1_2), "AES256-GCM-SHA384:@SECLEVEL=0").port)
    chosen = {a.key: a.cipher for a in rsa_only.versions}["TLSv1.2"]
    assert chosen == "AES256-GCM-SHA384" and not forward_secret(chosen)


@pytest.mark.parametrize(
    ("cipher", "expected"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", True),
        ("ECDHE-ECDSA-CHACHA20-POLY1305", True),
        ("DHE-RSA-AES128-SHA", True),
        ("EDH-RSA-DES-CBC3-SHA", True),
        ("TLS_AES_256_GCM_SHA384", True),  # TLS 1.3
        ("AES256-GCM-SHA384", False),  # the RSA key exchange
        ("AES128-SHA", False),
        ("ADH-AES256-GCM-SHA384", False),  # anonymous: ephemeral but unauthenticated
        ("", False),
    ],
)
def test_forward_secrecy_is_read_from_the_name_of_the_suite(cipher: str, expected: bool) -> None:
    assert forward_secret(cipher) is expected


def test_a_server_that_accepts_anonymous_suites_is_found_out(
    serve: Callable[..., TlsServer],
) -> None:
    result = probe(serve((V.TLSv1_2, V.TLSv1_2), "aNULL:@SECLEVEL=0").port)
    suite = {a.key: a for a in result.suites}["anonymous_or_null"]
    assert suite.status == "accepted"
    assert suite.cipher is not None and suite.cipher.startswith(("ADH", "AECDH"))


# ---------------------------------------------------------------------- what is not a TLS server


def test_a_closed_port_is_one_refused_connection_not_a_series_of_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []
    real = socket.create_connection

    def counting(address: tuple[str, int], *args: object, **kwargs: object) -> socket.socket:
        calls.append(address)
        return real(address, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("runner.tls_protocols.socket.create_connection", counting)
    result = probe(closed_port())
    assert result.refused and not result.reachable
    assert len(calls) == 1  # the other questions were not put
    assert {a.reason for a in result.attempts} == {"refused"}
    assert {a.status for a in result.attempts} == {"unknown"}


def test_plain_http_on_the_tls_port_is_rejected_as_not_tls() -> None:
    with TlsServer("plain") as server:
        result = probe(server.port)
    assert not result.reachable and not result.refused
    assert {a.status for a in result.versions} == {"rejected"}
    assert {a.reason for a in result.versions} == {"not_tls"}


def test_a_server_that_never_answers_is_unknown_and_costs_one_timeout() -> None:
    with TlsServer("silent") as server:
        result = probe_tls_protocols(HOST, server.port, ip_override=LOOPBACK, timeout=0.3)
    assert not result.reachable
    assert statuses(result)["TLSv1.2"] == "unknown"
    assert {a.reason for a in result.attempts} == {"timeout"}  # none was rejected on a guess


# ------------------------------------------------------------------------------ the client's limits


def test_a_question_this_client_cannot_put_is_not_testable_not_rejected(
    serve: Callable[..., TlsServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    import runner.tls_protocols as module

    real = module._context

    def without_tls_1_0(minimum: str, maximum: str, suites: str | None) -> ssl.SSLContext:
        if minimum == "TLSv1" and maximum == "TLSv1":
            raise ValueError("unsupported protocol")
        return real(minimum, maximum, suites)

    monkeypatch.setattr(module, "_context", without_tls_1_0)
    result = probe(serve((V.TLSv1_2, V.TLSv1_3), "DEFAULT").port)
    assert statuses(result)["TLSv1"] == "not_testable"
    assert {a.key: a for a in result.versions}["TLSv1"].reason == "unsupported_by_client"


def test_the_result_names_what_it_did_not_test_and_which_openssl_it_asked_with() -> None:
    assert {"SSLv3", "RC4", "3DES"} <= set(NOT_TESTED)
    assert VERSIONS == ("TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1")
    with TlsServer("silent") as server:
        data = probe_tls_protocols(HOST, server.port, ip_override=LOOPBACK, timeout=0.2).to_dict()
    assert data["openssl"] == ssl.OPENSSL_VERSION and data["connected_ip"] == LOOPBACK
    assert {"hostname", "port", "versions", "suites", "collected_at"} <= set(data)


def test_asking_for_deprecated_versions_does_not_warn(serve: Callable[..., TlsServer]) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        probe(serve((V.TLSv1_2, V.TLSv1_3), "DEFAULT").port)
    assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []


def test_the_time_budget_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    def never(*args: object, **kwargs: object) -> socket.socket:
        raise AssertionError("nothing may be asked once the budget is spent")

    monkeypatch.setattr("runner.tls_protocols.socket.create_connection", never)
    clock = iter([0.0] + [100.0] * 20)  # the deadline is taken at 0, every question is later
    result = probe_tls_protocols(
        HOST, 443, ip_override=LOOPBACK, budget=10.0, monotonic=lambda: next(clock)
    )
    assert {a.status for a in result.attempts} == {"unknown"}
    assert {a.reason for a in result.attempts} == {"budget_exceeded"}
    assert not result.reachable and not result.refused


# ---------------------------------------------------------------------- the gate and the codes


def test_only_a_numeric_public_address_is_connected_to(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # the gate as it is: loopback and private addresses are refused
    for address in ("127.0.0.1", "10.0.0.1", "not-an-address", "::1"):
        with pytest.raises(SSRFBlockedError):
            probe_tls_protocols(HOST, 443, ip_override=address)
    with pytest.raises(ValueError):
        probe_tls_protocols(HOST, 70000, ip_override="93.184.216.34")


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("TLSV1_ALERT_PROTOCOL_VERSION", ("rejected", "alert")),
        ("SSLV3_ALERT_HANDSHAKE_FAILURE", ("rejected", "alert")),
        ("TLSV1_ALERT_INSUFFICIENT_SECURITY", ("rejected", "alert")),
        ("UNSUPPORTED_PROTOCOL", ("rejected", "alert")),
        ("NO_SHARED_CIPHER", ("rejected", "alert")),
        ("UNEXPECTED_EOF_WHILE_READING", ("rejected", "closed")),
        ("WRONG_VERSION_NUMBER", ("rejected", "not_tls")),
        ("HTTP_REQUEST", ("rejected", "not_tls")),
        ("NO_PROTOCOLS_AVAILABLE", ("not_testable", "unsupported_by_client")),
        ("NO_CIPHERS_AVAILABLE", ("not_testable", "unsupported_by_client")),
        ("SOMETHING_NEW", ("unknown", "tls_error")),  # an unknown failure is never a refusal
        ("", ("unknown", "tls_error")),
    ],
)
def test_a_failed_handshake_is_classified_by_what_the_client_saw(
    reason: str, expected: tuple[str, str]
) -> None:
    error = ssl.SSLError(1, f"[SSL: {reason}] failed")
    error.reason = reason
    assert _classify(error) == expected


def test_an_attempt_serialises_with_stable_keys() -> None:
    attempt = Attempt("anonymous_or_null", "accepted", version="TLSv1.2", cipher="ADH-AES128-SHA")
    assert attempt.to_dict() == {
        "key": "anonymous_or_null",
        "status": "accepted",
        "version": "TLSv1.2",
        "cipher": "ADH-AES128-SHA",
        "reason": None,
    }
