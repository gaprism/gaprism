"""The Observatory check over recorded answers of Mozilla's API (2026-10-07), no network."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.checks.base import CachedAnswer, CheckContext, CheckOutcome
from app.checks.observatory import (
    CACHE_PROVIDER,
    SOURCE,
    URL,
    ObservatoryCheck,
    facts_of,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "domain"
GITHUB = json.loads((FIXTURES / "observatory_github.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((FIXTURES / "observatory_example.json").read_text(encoding="utf-8"))
UNRESOLVABLE = json.loads((FIXTURES / "observatory_unresolvable.json").read_text(encoding="utf-8"))
SCAN_FAILED = json.loads((FIXTURES / "observatory_scan_failed.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
ON: dict[str, Any] = {"EXTERNAL_DOMAIN_LOOKUPS": ["observatory"]}


class Cache:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], CachedAnswer] = {}
        self.now = NOW

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None:
        row = self.rows.get((provider, key))
        return None if row is None or row.fetched_at < self.now - max_age else row

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None:
        self.rows[(provider, key)] = CachedAnswer(status, payload, self.now)


class Mozilla:
    """A scripted API: ``answers`` maps the host asked about to ``(status, body)``; every request
    is recorded."""

    def __init__(self, answers: dict[str, tuple[int, Any]]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.answers.get(request.url.params["host"], (500, None))
        return httpx.Response(status, json=body) if body is not None else httpx.Response(status)

    @property
    def hosts(self) -> list[str]:
        return [r.url.params["host"] for r in self.requests]


def run(
    handler: Callable[[httpx.Request], httpx.Response],
    domain: str = "github.com",
    *,
    config: dict[str, Any] | None = None,
    cache: Cache | None = None,
) -> CheckOutcome:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = CheckContext(
        domain=domain,
        hostname=None,
        config=ON if config is None else config,
        http=http,
        cache=cache,
    )
    return ObservatoryCheck().run(ctx)


# ---------------------------------------------------------------------------- a grade


def test_a_scanned_domain_gets_its_grade_score_and_tests() -> None:
    mozilla = Mozilla({"github.com": (200, GITHUB)})
    outcome = run(mozilla)
    assert (outcome.status, outcome.source) == ("ok", SOURCE)
    data = outcome.data
    assert (data["grade"], data["score"], data["host"], data["domain"]) == (
        "A+",
        115,
        "github.com",
        "github.com",
    )
    assert (data["tests_passed"], data["tests_failed"], data["tests_quantity"]) == (11, 1, 12)
    assert data["details_url"] == GITHUB["details_url"] and data["status_code"] == 200
    assert (data["algorithm_version"], data["scanned_at"], data["cached"]) == (
        6,
        "2026-10-07T17:45:05.224Z",
        False,
    )
    assert data["tried"] == ["github.com"]


def test_the_request_is_one_post_with_the_host_and_nothing_else() -> None:
    mozilla = Mozilla({"github.com": (200, GITHUB)})
    run(mozilla)
    (request,) = mozilla.requests
    assert request.method == "POST" and str(request.url).startswith(URL)
    assert dict(request.url.params) == {"host": "github.com"}
    assert request.content == b""  # the name travels in the query, nothing about the scan


def test_a_low_grade_is_a_fact_not_a_failure() -> None:
    outcome = run(Mozilla({"example.com": (200, EXAMPLE)}), "example.com")
    assert outcome.status == "ok" and outcome.data["grade"] == "F" and outcome.data["score"] == 10


@pytest.mark.parametrize(
    "grade", ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]
)
def test_every_grade_of_the_scale_is_accepted(grade: str) -> None:
    body = {**GITHUB, "grade": grade}
    assert run(Mozilla({"github.com": (200, body)})).data["grade"] == grade


# ------------------------------------------------------------------- when it cannot scan


def test_a_name_mozilla_cannot_resolve_is_no_data_with_its_own_words_as_the_reason() -> None:
    outcome = run(Mozilla({"a.nowhere.example": (422, UNRESOLVABLE)}), "a.nowhere.example")
    assert (outcome.status, outcome.reason_code) == ("no_data", "invalid_hostname_lookup")
    assert outcome.data["api_error"] == "invalid-hostname-lookup"


def test_the_www_name_is_asked_when_the_apex_cannot_be_scanned() -> None:
    mozilla = Mozilla(
        {"vendor.example.com": (422, UNRESOLVABLE), "www.vendor.example.com": (200, GITHUB)}
    )
    outcome = run(mozilla, "vendor.example.com")  # not an apex: no second host
    assert mozilla.hosts == ["vendor.example.com"] and outcome.status == "no_data"

    mozilla = Mozilla({"vendor.com": (422, UNRESOLVABLE), "www.vendor.com": (200, GITHUB)})
    outcome = run(mozilla, "vendor.com")
    assert mozilla.hosts == ["vendor.com", "www.vendor.com"] and outcome.status == "ok"
    assert outcome.data["host"] == "www.vendor.com" and outcome.data["domain"] == "vendor.com"
    assert outcome.data["tried"] == ["vendor.com", "www.vendor.com"]


def test_when_neither_name_can_be_scanned_the_last_reason_is_kept_and_both_are_listed() -> None:
    mozilla = Mozilla({"vendor.com": (422, UNRESOLVABLE), "www.vendor.com": (422, SCAN_FAILED)})
    outcome = run(mozilla, "vendor.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "scan_failed")
    assert outcome.data["tried"] == ["vendor.com", "www.vendor.com"]


def test_a_name_that_is_not_a_site_at_all_is_not_asked_again_as_www() -> None:
    refused = {"error": "invalid-site", "message": "x is invalid: invalid site string"}
    mozilla = Mozilla({"vendor.com": (422, refused)})
    outcome = run(mozilla, "vendor.com")
    assert mozilla.hosts == ["vendor.com"] and outcome.reason_code == "invalid_site"


@pytest.mark.parametrize(
    ("response", "status", "reason"),
    [
        (httpx.Response(429), "unavailable", "rate_limited"),
        (httpx.Response(500), "error", "http_500"),
        (httpx.Response(503), "error", "http_503"),
        (httpx.Response(404), "error", "http_404"),
        (httpx.Response(200, text="<html>"), "error", "invalid_response"),
        (httpx.Response(200, json=["list"]), "error", "invalid_response"),
        (httpx.Response(200, json={"grade": "Z", "score": 1}), "error", "invalid_response"),
        (httpx.Response(200, json={**GITHUB, "score": "high"}), "error", "invalid_response"),
        (httpx.Response(200, json={**GITHUB, "tests_failed": -1}), "error", "invalid_response"),
        (httpx.Response(200, json={**GITHUB, "grade": None}), "error", "invalid_response"),
        (httpx.Response(200, json={**GITHUB, "error": "boom"}), "no_data", "boom"),
        (httpx.Response(422, text="not json"), "no_data", "not_scannable"),
    ],
)
def test_failures_are_typed_and_a_stray_answer_is_never_a_grade(
    response: httpx.Response, status: str, reason: str
) -> None:
    outcome = run(lambda request: response, "vendor.example.com")
    assert (outcome.status, outcome.reason_code) == (status, reason)
    assert "grade" not in outcome.data


def test_network_failures_are_typed_and_carry_no_exception_text() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret url inside", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret url inside", request=request)

    assert run(slow).reason_code == "timeout" and run(refused).reason_code == "connection_failed"
    assert "secret" not in repr(run(refused))


def test_a_timeout_or_a_rate_limit_does_not_send_a_second_request_for_www() -> None:
    mozilla = Mozilla({"vendor.com": (429, None)})
    assert run(mozilla, "vendor.com").reason_code == "rate_limited" and mozilla.hosts == [
        "vendor.com"
    ]


# ------------------------------------------------------------------------- what is trusted


def test_a_details_link_is_kept_only_when_it_points_to_mdn() -> None:
    elsewhere = {**GITHUB, "details_url": "https://evil.example/observatory?host=github.com"}
    assert run(Mozilla({"github.com": (200, elsewhere)})).data["details_url"] is None
    script = {**GITHUB, "details_url": "javascript:alert(1)"}
    assert run(Mozilla({"github.com": (200, script)})).data["details_url"] is None


def test_what_the_answer_carries_is_bounded() -> None:
    long = {**GITHUB, "scanned_at": "x" * 500, "details_url": GITHUB["details_url"] + "x" * 500}
    data = run(Mozilla({"github.com": (200, long)})).data
    assert len(data["scanned_at"]) == 40 and len(data["details_url"]) == 300


def test_the_facts_of_an_answer_leave_out_everything_else() -> None:
    answer = {**GITHUB, "secret": "x", "id": 1}
    facts = facts_of(answer)
    assert facts is not None and "secret" not in facts and "id" not in facts
    assert facts_of({**GITHUB, "score": True}) is None  # a bool is not a number here


def test_the_whole_result_is_plain_json() -> None:
    data = run(Mozilla({"github.com": (200, GITHUB)})).data
    assert json.loads(json.dumps(data)) == data


# ------------------------------------------------------------------- opt-in, and the cache


def test_without_the_setting_the_lookup_is_off_and_nobody_is_asked() -> None:
    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    for config in ({}, {"EXTERNAL_DOMAIN_LOOKUPS": ["rdap", "hsts_preload", "hibp"]}):
        outcome = run(never, config=config)
        assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")  # not a failure
    assert run(never, config={"EXTERNAL_DOMAIN_LOOKUPS": []}).reason_code == "disabled"


def test_the_answer_is_cached_for_a_day_and_failures_are_not() -> None:
    cache = Cache()
    first = run(Mozilla({"github.com": (200, GITHUB)}), cache=cache)
    assert first.data["cached"] is False and (CACHE_PROVIDER, "github.com") in cache.rows

    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    cache.now = NOW + timedelta(hours=23)
    again = run(never, cache=cache)
    assert again.data["cached"] is True and again.data["grade"] == "A+"

    cache.now = NOW + timedelta(hours=25)
    refreshed = run(Mozilla({"github.com": (200, EXAMPLE)}), cache=cache)
    assert refreshed.data["grade"] == "F" and refreshed.data["cached"] is False

    other = Cache()
    run(Mozilla({"github.com": (500, None)}), cache=other)
    assert other.rows == {}


def test_the_check_is_a_domain_check_with_no_prerequisites() -> None:
    check = ObservatoryCheck()
    assert (check.key, check.scope, check.needs) == ("observatory", "domain", ())
