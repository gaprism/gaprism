"""The TLS protocol rules, over what the real protocols check makes of the prober's answers."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.checks.base import CheckOutcome
from app.checks.tls_protocols import outcome_from_protocols
from app.rules import RULES
from tests.checks.test_tls_protocols_check import HOST, answers
from tests.rules.helpers import fire, host, one

PROTOCOL_RULES = (
    "TLS_LEGACY_PROTOCOL",
    "TLS_NO_MODERN_PROTOCOL",
    "TLS_NO_TLS13",
    "TLS_NULL_OR_ANONYMOUS_SUITES",
    "TLS_NO_FORWARD_SECRECY",
)


def facts(outcome: CheckOutcome) -> Any:
    return host(HOST, tls_protocols=outcome)


def checked(
    versions: dict[str, str] | None = None,
    suites: dict[str, str] | None = None,
    ciphers: dict[str, str] | None = None,
    reason: str | None = None,
) -> Any:
    return facts(outcome_from_protocols(answers(versions, suites, reason, ciphers)))


def firing(subject: Any) -> list[str]:
    return [rule_id for rule_id in PROTOCOL_RULES if fire(rule_id, subject)]


MODERN = {"TLSv1.2": "accepted", "TLSv1.3": "accepted"}


def test_a_server_with_the_current_versions_and_forward_secrecy_raises_nothing() -> None:
    assert firing(checked(MODERN)) == []


def test_a_host_whose_protocols_check_did_not_succeed_has_nothing_to_judge() -> None:
    for outcome in (
        CheckOutcome("error", "timeout"),
        CheckOutcome("no_data", "refused"),
        CheckOutcome("skipped", "no_public_address"),
    ):
        assert firing(facts(outcome)) == []
    assert firing(host(HOST)) == []  # scans from before the check existed


# ------------------------------------------------------------------------------ outdated versions


def test_old_versions_next_to_the_current_ones_are_medium() -> None:
    subject = checked({**MODERN, "TLSv1": "accepted", "TLSv1.1": "accepted"})
    draft = one("TLS_LEGACY_PROTOCOL", subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "medium",
        "high",
        "hostname_supported",
    )
    assert draft.params["versions"] == ["TLS 1.0", "TLS 1.1"]  # oldest first
    assert draft.params["modern"] == ["TLS 1.2", "TLS 1.3"]
    assert draft.subject == f"host:{HOST}" and draft.host_id == subject.id
    assert fire("TLS_NO_MODERN_PROTOCOL", subject) == []  # one problem is one finding


def test_one_old_version_is_enough() -> None:
    draft = one("TLS_LEGACY_PROTOCOL", checked({**MODERN, "TLSv1.1": "accepted"}))
    assert draft.params["versions"] == ["TLS 1.1"]


def test_only_old_versions_is_high_and_replaces_the_medium_finding() -> None:
    subject = checked({"TLSv1": "accepted"})
    draft = one("TLS_NO_MODERN_PROTOCOL", subject)
    assert (draft.severity, draft.confidence) == ("high", "high")
    assert draft.params["versions"] == ["TLS 1.0"]
    assert fire("TLS_LEGACY_PROTOCOL", subject) == []


def test_a_question_that_timed_out_is_not_a_refusal() -> None:
    """TLS 1.2 and 1.3 unanswered: nothing is known about them, so nothing is claimed."""
    subject = checked({"TLSv1": "accepted", "TLSv1.2": "unknown", "TLSv1.3": "unknown"})
    assert fire("TLS_NO_MODERN_PROTOCOL", subject) == []
    half = checked({"TLSv1": "accepted", "TLSv1.3": "unknown"})  # 1.2 refused, 1.3 unknown
    assert fire("TLS_NO_MODERN_PROTOCOL", half) == []


def test_a_client_that_could_not_offer_the_old_versions_says_nothing_about_them() -> None:
    subject = checked({**MODERN, "TLSv1": "not_testable", "TLSv1.1": "not_testable"})
    assert firing(subject) == []


# ------------------------------------------------------------------------------ TLS 1.3


def test_tls_1_2_without_tls_1_3_is_an_observation() -> None:
    draft = one("TLS_NO_TLS13", checked({"TLSv1.2": "accepted"}))
    assert (draft.severity, draft.confidence) == ("informational", "high")
    assert draft.params["versions"] == ["TLS 1.2"]


@pytest.mark.parametrize("status", ["unknown", "not_testable"])
def test_a_tls_1_3_question_that_was_not_answered_is_not_a_missing_tls_1_3(status: str) -> None:
    assert fire("TLS_NO_TLS13", checked({"TLSv1.2": "accepted", "TLSv1.3": status})) == []


def test_a_server_that_does_not_accept_tls_1_2_is_not_told_to_add_tls_1_3() -> None:
    assert fire("TLS_NO_TLS13", checked({"TLSv1": "accepted"})) == []


# ------------------------------------------------------------------------------ suites


def test_suites_without_encryption_or_authentication_are_high() -> None:
    subject = checked(
        MODERN, {"anonymous_or_null": "accepted"}, {"anonymous_or_null": "NULL-SHA256"}
    )
    draft = one("TLS_NULL_OR_ANONYMOUS_SUITES", subject)
    assert (draft.severity, draft.confidence) == ("high", "high")
    assert draft.params["cipher"] == "NULL-SHA256"


def test_a_server_that_refuses_them_is_not_reported() -> None:
    assert (
        fire("TLS_NULL_OR_ANONYMOUS_SUITES", checked(MODERN, {"anonymous_or_null": "rejected"}))
        == []
    )


def test_a_server_that_picks_a_suite_without_forward_secrecy_is_low() -> None:
    subject = checked(MODERN, ciphers={"TLSv1.2": "AES256-GCM-SHA384"})
    draft = one("TLS_NO_FORWARD_SECRECY", subject)
    assert (draft.severity, draft.confidence) == ("low", "high")
    assert draft.params["cipher"] == "AES256-GCM-SHA384"


@pytest.mark.parametrize(
    "cipher", ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "DHE-RSA-AES128-SHA"]
)
def test_a_server_that_picks_an_ephemeral_suite_is_not_reported(cipher: str) -> None:
    assert fire("TLS_NO_FORWARD_SECRECY", checked(MODERN, ciphers={"TLSv1.2": cipher})) == []


def test_only_the_choice_in_a_tls_1_2_handshake_counts() -> None:
    """A TLS 1.0 server's static RSA suite is already part of its High finding."""
    subject = checked({"TLSv1": "accepted"}, ciphers={"TLSv1": "AES256-SHA"})
    assert fire("TLS_NO_FORWARD_SECRECY", subject) == []


# ------------------------------------------------------------------------------ the whole


def test_the_findings_are_plain_json_and_every_rule_is_documented() -> None:
    subject = checked(
        {**MODERN, "TLSv1": "accepted"},
        {"anonymous_or_null": "accepted"},
        {"TLSv1.2": "AES256-GCM-SHA384"},
    )
    for rule_id in PROTOCOL_RULES:
        for draft in fire(rule_id, subject):
            assert json.loads(json.dumps(draft.params)) == draft.params
    assert firing(subject) == [
        "TLS_LEGACY_PROTOCOL",
        "TLS_NULL_OR_ANONYMOUS_SUITES",
        "TLS_NO_FORWARD_SECRECY",
    ]
    for rule_id in PROTOCOL_RULES:
        rule = RULES[rule_id]
        assert rule.checks == ("tls_protocols",) and rule.trigger and rule.advice
