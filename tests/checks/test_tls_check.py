"""The TLS check: which address it uses, and how probe results become typed outcomes."""

from __future__ import annotations

import datetime
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.tls import MAX_SANS, TlsCheck, failure_codes, outcome_from_probe
from runner.dns import SSRFBlockedError
from runner.tls import TLSProbeResult

NOW = datetime.datetime(2026, 10, 4, tzinfo=datetime.UTC)
DNS_OK = CheckOutcome(
    "ok", data={"addresses": ["93.184.216.34", "2606:2800:220:1::1"], "blocked": []}
)


def probe_result(**fields: Any) -> TLSProbeResult:
    """A valid certificate unless the test says otherwise."""
    values: dict[str, Any] = {
        "hostname": "www.example.com",
        "port": 443,
        "connected_ip": "93.184.216.34",
        "is_valid": True,
        "chain_trust": True,
        "hostname_match": True,
        "time_valid": True,
        "not_before": NOW - datetime.timedelta(days=30),
        "not_after": NOW + datetime.timedelta(days=60),
        "days_until_expiration": 60,
        "subject_cn": "www.example.com",
        "issuer_cn": "Example CA",
        "issuer_org": "Example Org",
        "sans": ["www.example.com", "example.com"],
        "serial_number": "0A1B",
        "fingerprint_sha256": "ab" * 32,
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "protocol_version": "TLSv1.3",
        "alpn_negotiated": "h2",
        "key_type": "EC",
        "key_bits": 256,
        "key_curve": "secp256r1",
        "signature_algorithm": "ecdsa-with-SHA256",
        "signature_hash": "sha256",
        "chain_length": 3,
        "chain_subjects": ["CN=www.example.com", "CN=Example CA", "CN=Example Root"],
    }
    values.update(fields)
    return TLSProbeResult(**values)


def no_certificate(*reasons: str) -> TLSProbeResult:
    return TLSProbeResult(
        hostname="www.example.com",
        port=443,
        connected_ip="93.184.216.34",
        is_valid=False,
        chain_trust=False,
        hostname_match=False,
        time_valid=False,
        failure_reasons=list(reasons),
    )


class FakeProber:
    def __init__(self, result: TLSProbeResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, hostname: str, port: int, **kwargs: Any) -> TLSProbeResult:
        self.calls.append((hostname, port, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def run(prober: FakeProber, previous: dict[str, CheckOutcome] | None = None, **config: Any) -> Any:
    ctx = CheckContext(
        domain="example.com",
        hostname="www.example.com",
        config=config,
        http=httpx.Client(),
        previous={"dns": DNS_OK} if previous is None else previous,
    )
    return TlsCheck(prober=prober).run(ctx)


# ------------------------------------------------------------------------------ the address


def test_the_first_screened_address_from_dns_is_used_and_nothing_else_is_resolved() -> None:
    prober = FakeProber(probe_result())
    run(prober, EGRESS_CONNECT_TIMEOUT_SEC=7)
    hostname, port, kwargs = prober.calls[0]
    assert (hostname, port) == ("www.example.com", 443)
    assert kwargs == {"ip_override": "93.184.216.34", "timeout": 7.0}


def test_without_a_usable_address_the_check_is_skipped_not_failed() -> None:
    prober = FakeProber(probe_result())
    blocked = {"addresses": [], "blocked": [{"ip": "10.0.0.5", "reason": "private"}]}
    outcome = run(prober, {"dns": CheckOutcome("ok", data=blocked)})
    assert (outcome.status, outcome.reason_code) == ("skipped", "no_public_address")
    assert outcome.data == {"blocked": blocked["blocked"]}
    assert prober.calls == []  # never connected


def test_a_gate_refusal_is_an_error_with_a_reason_not_a_crash() -> None:
    outcome = run(FakeProber(SSRFBlockedError("TLS destination is not a public IP.")))
    assert (outcome.status, outcome.reason_code) == ("error", "blocked_destination")


# ------------------------------------------------------------------------------ the outcomes


def test_a_valid_certificate_is_ok_with_all_facts() -> None:
    outcome = run(FakeProber(probe_result()))
    assert (outcome.status, outcome.source) == ("ok", "tls-probe")
    data = outcome.data
    assert data["verified"] is True and data["failures"] == [] and data["forensic"] is False
    assert (data["protocol"], data["cipher"], data["alpn"]) == (
        "TLSv1.3",
        "TLS_AES_256_GCM_SHA384",
        "h2",
    )
    assert (data["chain_length"], len(data["chain_subjects"])) == (3, 3)
    certificate = data["certificate"]
    assert certificate["days_remaining"] == 60 and certificate["san_count"] == 2
    assert certificate["not_after"] == (NOW + datetime.timedelta(days=60)).isoformat()
    assert (certificate["key_type"], certificate["key_bits"], certificate["key_curve"]) == (
        "EC",
        256,
        "secp256r1",
    )
    assert certificate["signature_algorithm"] == "ecdsa-with-SHA256"


def test_a_bad_certificate_is_still_ok_because_the_facts_were_collected() -> None:
    expired = probe_result(
        is_valid=False,
        chain_trust=False,
        time_valid=False,
        failure_reasons=["CERTIFICATE_EXPIRED", "HOSTNAME_MISMATCH"],
        days_until_expiration=-12,
        forensic=True,
    )
    outcome = run(FakeProber(expired))
    assert outcome.status == "ok"
    assert outcome.data["verified"] is False and outcome.data["forensic"] is True
    assert outcome.data["failures"] == ["expired", "hostname_mismatch"]
    assert outcome.data["certificate"]["days_remaining"] == -12


def test_nothing_listening_on_443_is_no_data_not_an_error() -> None:
    outcome = run(FakeProber(no_certificate("CONNECTION_REFUSED")))
    assert (outcome.status, outcome.reason_code) == ("no_data", "refused")


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        ("TIMEOUT", "timeout"),
        ("CONNECTION_FAILED: [Errno 101] Network is unreachable", "connection_failed"),
        ("TLS_HANDSHAKE_FAILED: wrong version number", "handshake_failed"),
        ("SOMETHING_NEW", "other"),
    ],
)
def test_failing_to_get_any_certificate_is_an_error_with_a_typed_reason(
    reason: str, code: str
) -> None:
    outcome = run(FakeProber(no_certificate(reason)))
    assert (outcome.status, outcome.reason_code) == ("error", code)
    assert outcome.data["failures"] == [code]


def test_the_failure_codes_are_stable_deduplicated_and_ordered() -> None:
    assert failure_codes(
        [
            "CERTIFICATE_EXPIRED",
            "UNTRUSTED_ROOT",
            "CERTIFICATE_EXPIRED",
            "CERTIFICATE_VERIFY_FAILED: unsupported purpose",
        ]
    ) == ["expired", "untrusted", "verify_failed"]
    assert failure_codes([]) == []


def test_a_certificate_with_thousands_of_names_is_bounded() -> None:
    names = [f"h{n}.example.com" for n in range(MAX_SANS + 400)]
    outcome = outcome_from_probe(probe_result(sans=names, subject_cn="x" * 500))
    certificate = outcome.data["certificate"]
    assert len(certificate["sans"]) == MAX_SANS and certificate["san_count"] == MAX_SANS + 400
    assert len(certificate["subject_cn"]) == 200


def test_a_serial_number_that_is_not_positive_is_part_of_the_facts() -> None:
    outcome = outcome_from_probe(probe_result(serial_number="-5", serial_positive=False))
    assert outcome.status == "ok"
    certificate = outcome.data["certificate"]
    assert (certificate["serial"], certificate["serial_positive"]) == ("-5", False)
    assert (
        outcome_from_probe(probe_result(serial_positive=True)).data["certificate"][
            "serial_positive"
        ]
        is True
    )


def test_a_certificate_that_was_presented_and_cannot_be_read_is_an_error_with_that_reason() -> None:
    outcome = outcome_from_probe(no_certificate("CERTIFICATE_UNREADABLE"))
    assert (outcome.status, outcome.reason_code) == ("error", "certificate_unreadable")
    assert outcome.data["failures"] == ["certificate_unreadable"]
