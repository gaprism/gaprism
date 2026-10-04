"""Network-free regression tests for target collection and evidence integrity."""

import ipaddress
from unittest.mock import Mock

import pytest
from _pytest.monkeypatch import MonkeyPatch

from app.service.checks.tls import evaluate_tls_check
from runner.dns import SSRFBlockedError
from runner.tls import TLSProbeResult, probe_tls_endpoint


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "10.0.0.1"])
def test_tls_private_override_never_opens_socket(monkeypatch: MonkeyPatch, address: str) -> None:
    connect = Mock(side_effect=AssertionError("socket must not open"))
    monkeypatch.setattr("runner.tls.socket.create_connection", connect)
    with pytest.raises(SSRFBlockedError):
        probe_tls_endpoint("example.com", ip_override=address)
    connect.assert_not_called()


def test_tls_uses_numeric_screened_address(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        "runner.tls.resolve_and_screen", lambda host: [ipaddress.ip_address("8.8.8.8")]
    )
    connect = Mock(side_effect=ConnectionRefusedError())
    monkeypatch.setattr("runner.tls.socket.create_connection", connect)
    result = probe_tls_endpoint("example.com")
    assert not result.is_valid
    assert connect.call_args.args[0] == ("8.8.8.8", 443)


@pytest.mark.parametrize("failure", ["TIMEOUT", "CONNECTION_REFUSED", "CONNECTION_FAILED: error"])
def test_unreachable_endpoint_is_unknown_not_invalid_certificate(failure: str) -> None:
    result = TLSProbeResult(
        "example.com", 443, None, False, False, False, False, failure_reasons=[failure]
    )
    evaluated = evaluate_tls_check(result)
    assert evaluated.verdict == "unknown"
    assert evaluated.should_skip_http
    assert [finding.rule_id for finding in evaluated.findings] == ["COLLECTION_INCOMPLETE"]
