"""The TLS protocols check over a fake prober: typed outcomes, bounds, no network."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome, waits_for
from app.checks.tls_protocols import TlsProtocolsCheck, outcome_from_protocols
from runner.dns import SSRFBlockedError
from runner.tls_protocols import NOT_TESTED, VERSIONS, Attempt, TLSProtocolsResult

HOST = "www.example.com"
IP = "93.184.216.34"


def dns(*addresses: str) -> CheckOutcome:
    return CheckOutcome("ok", data={"addresses": list(addresses), "blocked": []})


def attempt(key: str, status: str, reason: str | None = None, cipher: str | None = None) -> Attempt:
    version = key if status == "accepted" and key.startswith("TLS") else None
    return Attempt(key, status, version=version, cipher=cipher, reason=reason)


DEFAULT_CIPHERS = {
    "TLSv1.3": "TLS_AES_256_GCM_SHA384",
    "TLSv1.2": "ECDHE-RSA-AES256-GCM-SHA384",
    "TLSv1.1": "ECDHE-RSA-AES256-SHA",
    "TLSv1": "ECDHE-RSA-AES256-SHA",
    "anonymous_or_null": "ADH-AES256-GCM-SHA384",
}


def answers(
    versions: dict[str, str] | None = None,
    suites: dict[str, str] | None = None,
    reason: str | None = None,
    ciphers: dict[str, str] | None = None,
) -> TLSProtocolsResult:
    """A result: ``versions`` and ``suites`` map a key to its status (``reason`` for the others);
    ``ciphers`` overrides the suite an accepted question was answered with."""
    chosen = {**DEFAULT_CIPHERS, **(ciphers or {})}
    asked = versions or {"TLSv1.2": "accepted", "TLSv1.3": "accepted"}
    version_list = [
        attempt(
            key,
            asked.get(key, "rejected"),
            None if asked.get(key) == "accepted" else reason,
            chosen[key] if asked.get(key) == "accepted" else None,
        )
        for key in VERSIONS
    ]
    kinds = suites or {}
    suite_list = [
        attempt(
            key,
            kinds.get(key, "rejected"),
            None if kinds.get(key) == "accepted" else reason,
            chosen[key] if kinds.get(key) == "accepted" else None,
        )
        for key in ("anonymous_or_null",)
    ]
    return TLSProtocolsResult(HOST, 443, IP, version_list, suite_list, openssl="OpenSSL 3.0.18")


class FakeProber:
    def __init__(self, result: TLSProtocolsResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> TLSProtocolsResult:
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def run(
    prober: FakeProber, previous: dict[str, CheckOutcome] | None = None, **config: Any
) -> CheckOutcome:
    ctx = CheckContext(
        domain="example.com",
        hostname=HOST,
        config=config,
        http=httpx.Client(),
        previous={"dns": dns(IP)} if previous is None else previous,
    )
    return TlsProtocolsCheck(prober=prober).run(ctx)


# ------------------------------------------------------------------------------ the contract


def test_it_is_a_host_check_that_needs_the_dns_answer_and_not_the_certificate() -> None:
    check = TlsProtocolsCheck()
    assert (check.key, check.scope, check.needs) == ("tls_protocols", "host", ("dns",))
    assert waits_for(check) == ("dns",)  # a server with only old versions has no certificate read


def test_the_first_screened_address_is_asked_with_a_bounded_time() -> None:
    prober = FakeProber(answers())
    run(prober, {"dns": dns(IP, "93.184.216.35")}, EGRESS_CONNECT_TIMEOUT_SEC=30)
    ((args, kwargs),) = prober.calls
    assert args == (HOST, 443) and kwargs == {
        "ip_override": IP,
        "timeout": 5.0,
    }  # never more than 5 s
    short = FakeProber(answers())
    run(short, EGRESS_CONNECT_TIMEOUT_SEC=2)
    assert short.calls[0][1]["timeout"] == 2.0


def test_without_a_public_address_nothing_is_asked() -> None:
    prober = FakeProber(answers())
    for previous in ({}, {"dns": dns()}):
        outcome = run(prober, previous)
        assert (outcome.status, outcome.reason_code) == ("skipped", "no_public_address")
    assert prober.calls == []


def test_a_destination_the_gate_refuses_is_an_error() -> None:
    outcome = run(FakeProber(SSRFBlockedError("not public")))
    assert (outcome.status, outcome.reason_code) == ("error", "blocked_destination")


# ------------------------------------------------------------------------------ the outcomes


def test_what_the_server_accepts_is_kept_question_by_question() -> None:
    result = answers(
        {"TLSv1.2": "accepted", "TLSv1.3": "accepted", "TLSv1": "accepted"},
        {"anonymous_or_null": "accepted"},
    )
    outcome = outcome_from_protocols(result)
    assert (outcome.status, outcome.source) == ("ok", "tls-probe")
    data = outcome.data
    assert data["accepted"] == ["TLSv1.2", "TLSv1.3", "TLSv1"]
    assert [v["key"] for v in data["versions"]] == list(VERSIONS)
    assert {s["key"]: s["status"] for s in data["suites"]} == {"anonymous_or_null": "accepted"}
    assert data["ip"] == IP and data["port"] == 443 and data["openssl"] == "OpenSSL 3.0.18"


def test_what_could_not_be_asked_is_named_so_that_silence_is_not_read_as_safe() -> None:
    data = outcome_from_protocols(answers()).data
    assert data["not_tested"] == list(NOT_TESTED) and "SSLv3" in data["not_tested"]


def test_a_closed_port_is_no_data() -> None:
    refused = answers({"TLSv1.2": "unknown"}, reason="refused")
    outcome = outcome_from_protocols(refused)
    assert (outcome.status, outcome.reason_code) == ("no_data", "refused")


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        ("timeout", "timeout"),
        ("not_tls", "not_tls"),
        ("alert", "no_handshake"),
        ("closed", "no_handshake"),
    ],
)
def test_a_server_that_completed_no_handshake_is_inconclusive_never_unsupported(
    reason: str, code: str
) -> None:
    result = answers({key: "rejected" for key in VERSIONS}, reason=reason)
    outcome = outcome_from_protocols(result)
    assert (outcome.status, outcome.reason_code) == ("error", code)
    assert outcome.data["accepted"] == [] and outcome.data["versions"]  # the answers are kept


def test_one_accepted_handshake_of_any_age_is_enough_to_judge() -> None:
    only_old = answers({"TLSv1": "accepted"})
    outcome = outcome_from_protocols(only_old)
    assert outcome.status == "ok" and outcome.data["accepted"] == ["TLSv1"]


def test_an_accepted_answer_says_whether_its_suite_gives_forward_secrecy() -> None:
    chosen = {"TLSv1.2": "AES256-GCM-SHA384", "TLSv1.3": "TLS_AES_128_GCM_SHA256"}
    data = outcome_from_protocols(answers(ciphers=chosen)).data
    flags = {v["key"]: v["forward_secret"] for v in data["versions"]}
    assert flags == {"TLSv1.2": False, "TLSv1.3": True, "TLSv1.1": None, "TLSv1": None}
    assert data["suites"][0]["forward_secret"] is None  # nothing was accepted, nothing to say
    ephemeral = outcome_from_protocols(answers({"TLSv1.2": "accepted"})).data
    assert ephemeral["versions"][0]["forward_secret"] is True  # ECDHE
