"""The Observatory check against Mozilla's real API. Needs the network: ``pytest -m live``.

``example.com`` is IANA's reserved example site, which anybody may have scanned (the scan history is
public on MDN either way). The tests notice when the API changes its answers, and confirm the shapes
that the recorded fixtures of ``test_observatory_check`` were taken from.
"""

from __future__ import annotations

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.observatory import DETAILS_PREFIX, GRADE, ObservatoryCheck

pytestmark = pytest.mark.live

CONFIG = {"EXTERNAL_DOMAIN_LOOKUPS": ["observatory"]}


def scan(domain: str) -> CheckOutcome:
    with httpx.Client(timeout=60, headers={"User-Agent": "WebDueDiligence-live-test"}) as client:
        context = CheckContext(domain=domain, hostname=None, config=CONFIG, http=client)
        return ObservatoryCheck().run(context)


def test_a_real_site_gets_a_grade_in_the_shape_the_fixtures_have() -> None:
    outcome = scan("example.com")
    assert outcome.status == "ok", (outcome.reason_code, outcome.data)
    data = outcome.data
    assert GRADE.fullmatch(data["grade"]) and 0 <= data["score"] <= 145
    assert data["tests_passed"] + data["tests_failed"] == data["tests_quantity"] > 0
    assert data["details_url"].startswith(DETAILS_PREFIX) and "example.com" in data["details_url"]
    assert data["host"] == "example.com" and data["tried"] == ["example.com"]
    assert data["scanned_at"] and data["algorithm_version"]


def test_a_name_that_does_not_resolve_is_no_data_with_the_apis_own_reason() -> None:
    outcome = scan("this-name-does-not-exist-wdd-probe.example.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "invalid_hostname_lookup")
    assert outcome.data["api_error"] == "invalid-hostname-lookup" and "grade" not in outcome.data
