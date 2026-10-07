"""The protocol prober against real servers. Needs the network: run with ``pytest -m live``.

badssl.com runs servers that are misconfigured on purpose, one per fault; github.com is an
ordinary modern server. These notice when a test server changes, and confirm that the answers of
the prober match what those servers are known to do.
"""

from __future__ import annotations

import socket

import pytest

from runner.tls_protocols import TLSProtocolsResult, forward_secret, probe_tls_protocols

pytestmark = pytest.mark.live


def ask(host: str, port: int = 443) -> TLSProtocolsResult:
    found = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    return probe_tls_protocols(host, port, ip_override=found[0][4][0], timeout=8)


def statuses(result: TLSProtocolsResult) -> dict[str, str]:
    return {attempt.key: attempt.status for attempt in result.attempts}


def test_a_server_that_speaks_only_tls_1_0() -> None:
    result = ask("tls-v1-0.badssl.com", 1010)
    assert result.accepted() == ["TLSv1"] and result.reachable


def test_a_server_that_speaks_only_tls_1_1() -> None:
    result = ask("tls-v1-1.badssl.com", 1011)
    assert result.accepted() == ["TLSv1.1"]


def test_a_server_that_speaks_only_tls_1_2() -> None:
    result = ask("tls-v1-2.badssl.com", 1012)
    assert result.accepted() == ["TLSv1.2"]
    assert statuses(result)["TLSv1.3"] == "rejected"


def test_a_server_that_accepts_suites_without_encryption() -> None:
    result = ask("null.badssl.com")
    weak = {a.key: a for a in result.suites}["anonymous_or_null"]
    assert weak.status == "accepted" and weak.cipher is not None and "NULL" in weak.cipher.upper()


def test_a_server_that_chooses_the_rsa_key_exchange() -> None:
    result = ask("static-rsa.badssl.com")
    chosen = {a.key: a for a in result.versions}["TLSv1.2"]
    assert chosen.status == "accepted" and chosen.cipher is not None
    assert not forward_secret(chosen.cipher)


def test_an_ordinary_modern_server_accepts_the_current_versions_only() -> None:
    result = ask("github.com")
    assert result.accepted() == ["TLSv1.2", "TLSv1.3"]
    assert {a.status for a in result.suites} == {"rejected"}
    chosen = {a.key: a for a in result.versions}["TLSv1.2"]
    assert chosen.cipher is not None and forward_secret(chosen.cipher)


@pytest.mark.parametrize("host", ["rc4.badssl.com", "3des.badssl.com"])
def test_a_server_that_offers_only_what_this_client_cannot_speak_is_inconclusive(host: str) -> None:
    """RC4 and 3DES are not in this OpenSSL: no question can be answered, and none is guessed."""
    result = ask(host)
    assert not result.reachable and not result.refused
    assert {a.status for a in result.attempts} == {"rejected"}
