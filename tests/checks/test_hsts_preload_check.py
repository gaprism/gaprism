"""The HSTS preload check over recorded hstspreload.org answers and a mock transport."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.checks.base import CachedAnswer, CheckContext, CheckOutcome
from app.checks.hsts_preload import STATES, HstsPreloadCheck

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "domain"
GITHUB = json.loads((FIXTURES / "hstspreload_github.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((FIXTURES / "hstspreload_example.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


class Cache:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], CachedAnswer] = {}
        self.now = NOW

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None:
        row = self.rows.get((provider, key))
        return None if row is None or row.fetched_at < self.now - max_age else row

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None:
        self.rows[(provider, key)] = CachedAnswer(status, payload, self.now)


def run(
    handler: Callable[[httpx.Request], httpx.Response],
    domain: str = "github.com",
    *,
    config: dict[str, Any] | None = None,
    cache: Cache | None = None,
) -> CheckOutcome:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = CheckContext(domain=domain, hostname=None, config=config or {}, http=http, cache=cache)
    return HstsPreloadCheck().run(ctx)


def answering(body: Any, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(status, json=body)


def test_a_preloaded_domain_is_reported_as_such() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=GITHUB)

    outcome = run(handler)
    assert (outcome.status, outcome.source) == ("ok", "hstspreload.org")
    data = outcome.data
    assert (data["status"], data["preloaded"], data["domain"]) == ("preloaded", True, "github.com")
    assert data["preloaded_domain"] == "github.com" and data["cached"] is False
    assert str(seen[0].url) == "https://hstspreload.org/api/v2/status?domain=github.com"


def test_a_domain_that_is_not_listed_is_a_fact_not_a_failure() -> None:
    outcome = run(answering(EXAMPLE), "example.com")
    assert outcome.status == "ok"
    assert (outcome.data["status"], outcome.data["preloaded"]) == ("unknown", False)
    assert outcome.data["preloaded_domain"] is None  # the empty string means "none"


@pytest.mark.parametrize("state", STATES)
def test_every_state_the_service_knows(state: str) -> None:
    outcome = run(answering({"name": "x.example", "status": state, "preloadedDomain": ""}))
    assert outcome.data["status"] == state and outcome.data["preloaded"] is (state == "preloaded")


@pytest.mark.parametrize(
    ("response", "status", "reason"),
    [
        (httpx.Response(429), "unavailable", "rate_limited"),
        (httpx.Response(500), "error", "http_500"),
        (httpx.Response(404), "error", "http_404"),
        (httpx.Response(200, text="<html>"), "error", "invalid_response"),
        (httpx.Response(200, json=["list"]), "error", "invalid_response"),
        (httpx.Response(200, json={"status": "banana"}), "error", "invalid_response"),
        (httpx.Response(200, json={"name": "x"}), "error", "invalid_response"),
    ],
)
def test_failures_are_typed(response: httpx.Response, status: str, reason: str) -> None:
    outcome = run(lambda request: response)
    assert (outcome.status, outcome.reason_code) == (status, reason)


def test_network_failures_are_typed_and_carry_no_exception_text() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret url inside", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret url inside", request=request)

    assert run(slow).reason_code == "timeout" and run(refused).reason_code == "connection_failed"
    assert "secret" not in repr(run(refused))


def test_the_domain_is_quoted_into_the_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=EXAMPLE)

    run(handler, "a&b=c.example.com")  # cannot happen (scopes are validated), but never inject
    assert seen[0].url.params["domain"] == "a&b=c.example.com" and len(seen[0].url.params) == 1


def test_a_switched_off_lookup_asks_nobody() -> None:
    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    outcome = run(never, config={"EXTERNAL_DOMAIN_LOOKUPS": ["rdap", "hibp"]})
    assert (outcome.status, outcome.reason_code) == ("unavailable", "disabled")


def test_the_answer_is_cached_for_a_day_and_failures_are_not() -> None:
    cache = Cache()
    first = run(answering(GITHUB), cache=cache)
    assert first.data["cached"] is False and ("hstspreload", "github.com") in cache.rows

    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    cache.now = NOW + timedelta(hours=23)
    again = run(never, cache=cache)
    assert again.data["cached"] is True and again.data["status"] == "preloaded"

    cache.now = NOW + timedelta(hours=25)
    refreshed = run(answering(EXAMPLE), cache=cache)
    assert refreshed.data["status"] == "unknown" and refreshed.data["cached"] is False

    other = Cache()
    run(lambda request: httpx.Response(500), cache=other)
    assert other.rows == {}
