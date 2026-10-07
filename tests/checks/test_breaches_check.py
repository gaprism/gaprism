"""The breach-history check over recorded Have I Been Pwned answers and a mock transport."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

import app.checks.breaches as module
from app.checks.base import CachedAnswer, CheckContext, CheckOutcome
from app.checks.breaches import MAX_BREACHES, BreachesCheck, parse_breach

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "domain"
ADOBE = json.loads((FIXTURES / "hibp_adobe.json").read_text(encoding="utf-8"))
LINKEDIN = json.loads((FIXTURES / "hibp_linkedin.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


class NoWait:
    """A rate limiter that never sleeps, and counts how often it was asked."""

    def __init__(self) -> None:
        self.acquired = 0

    def acquire(self) -> float:
        self.acquired += 1
        return 0.0


class FakeLimiters:
    def __init__(self) -> None:
        self.limiter = NoWait()
        self.asked: list[tuple[str, float]] = []

    def get(self, name: str, per_second: float) -> NoWait:
        self.asked.append((name, per_second))
        return self.limiter


@pytest.fixture(autouse=True)
def limiters(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeLimiters]:
    fake = FakeLimiters()
    monkeypatch.setattr(module, "LIMITERS", fake)
    yield fake


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
    domain: str = "adobe.com",
    *,
    config: dict[str, Any] | None = None,
    cache: Cache | None = None,
) -> CheckOutcome:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = CheckContext(domain=domain, hostname=None, config=config or {}, http=http, cache=cache)
    return BreachesCheck().run(ctx)


def answering(body: Any, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(status, json=body)


# ------------------------------------------------------------------------------ real answers


def test_a_known_breach_is_reported_with_facts_and_without_hibps_html() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=ADOBE)

    outcome = run(handler)
    assert (outcome.status, outcome.reason_code, outcome.source) == ("ok", None, "hibp")
    data = outcome.data
    assert (data["domain"], data["queried"], data["total"]) == ("adobe.com", "adobe.com", 1)
    assert data["latest_breach_date"] == "2013-10-04"
    (breach,) = data["breaches"]
    assert (breach["name"], breach["title"], breach["domain"]) == ("Adobe", "Adobe", "adobe.com")
    assert (breach["breach_date"], breach["added_date"]) == ("2013-10-04", "2013-12-04")
    assert breach["pwn_count"] == 152445165
    assert breach["data_classes"] == ["Email addresses", "Password hints", "Passwords", "Usernames"]
    assert (
        breach["verified"] is True
        and breach["fabricated"] is False
        and breach["spam_list"] is False
    )
    assert "Description" not in json.dumps(data) and "<a href" not in json.dumps(data)
    assert seen[0].url.params["domain"] == "adobe.com" and str(seen[0].url).startswith(
        "https://haveibeenpwned.com/api/v3/breaches?"
    )


def test_several_breaches_come_newest_first_with_their_flags() -> None:
    data = run(answering(LINKEDIN), "linkedin.com").data
    assert data["total"] == 3 and data["latest_breach_date"] == "2023-11-04"
    assert [b["name"] for b in data["breaches"]] == [
        "LinkedInScrape2023",
        "LinkedInScrape",
        "LinkedIn",
    ]
    assert data["breaches"][0]["spam_list"] is True  # a scrape, marked as such
    assert data["breaches"][2]["spam_list"] is False


def test_no_breach_is_no_data_and_never_clean() -> None:
    outcome = run(answering([]), "example.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_breach_known")
    assert outcome.data["total"] == 0 and outcome.data["breaches"] == []
    assert outcome.data["latest_breach_date"] is None


def test_the_breached_service_is_the_registrable_domain() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=ADOBE)

    outcome = run(handler, "account.eu.adobe.com")
    assert seen[0].url.params["domain"] == "adobe.com"
    assert (outcome.data["domain"], outcome.data["queried"]) == (
        "account.eu.adobe.com",
        "adobe.com",
    )


# ------------------------------------------------------------------------------ failures


@pytest.mark.parametrize(
    ("response", "status", "reason"),
    [
        (httpx.Response(429), "unavailable", "rate_limited"),
        (httpx.Response(401), "error", "http_401"),
        (httpx.Response(503), "error", "http_503"),
        (httpx.Response(200, text="<html>"), "error", "invalid_response"),
        (httpx.Response(200, json={"not": "a list"}), "error", "invalid_response"),
    ],
)
def test_failures_are_typed(response: httpx.Response, status: str, reason: str) -> None:
    outcome = run(lambda request: response)
    assert (outcome.status, outcome.reason_code) == (status, reason)


def test_network_failures_are_typed_and_carry_no_exception_text() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("boom", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    assert run(slow).reason_code == "timeout" and run(refused).reason_code == "connection_failed"


def test_the_lookup_can_be_switched_off() -> None:
    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    outcome = run(never, config={"EXTERNAL_DOMAIN_LOOKUPS": ["rdap", "hsts_preload"]})
    assert (outcome.status, outcome.reason_code) == ("skipped", "disabled")  # a decision, no gap


def test_calls_go_through_the_shared_rate_limiter(limiters: FakeLimiters) -> None:
    run(answering(ADOBE))
    run(answering(ADOBE))
    assert limiters.asked == [("hibp", 0.5), ("hibp", 0.5)] and limiters.limiter.acquired == 2


# ------------------------------------------------------------------------------ the cache


def test_answers_and_empty_answers_are_cached_and_failures_are_not(limiters: FakeLimiters) -> None:
    cache = Cache()
    run(answering(ADOBE), cache=cache)
    run(answering([]), "example.com", cache=cache)
    run(lambda request: httpx.Response(500), "failing.example", cache=cache)
    assert {key for key in cache.rows} == {("hibp", "adobe.com"), ("hibp", "example.com")}

    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be asked")

    asked = limiters.limiter.acquired
    hit = run(never, cache=cache)
    assert hit.status == "ok" and hit.data["cached"] is True and hit.data["total"] == 1
    empty = run(never, "example.com", cache=cache)
    assert (empty.status, empty.reason_code, empty.data["cached"]) == (
        "no_data",
        "no_breach_known",
        True,
    )
    assert limiters.limiter.acquired == asked  # cached answers cost no rate-limit slot

    cache.now = NOW + timedelta(hours=25)
    assert run(answering(LINKEDIN), cache=cache).data["total"] == 3  # stale: asked again


# ------------------------------------------------------------------------------ parsing


def test_odd_entries_never_crash_and_are_bounded() -> None:
    assert (
        parse_breach("nope") is None
        and parse_breach({}) is None
        and parse_breach({"Name": ""}) is None
    )
    parsed = parse_breach(
        {
            "Name": "X" * 500,
            "Title": 7,
            "Domain": "example.com",
            "BreachDate": "not a date",
            "AddedDate": "2020-01-02T03:04:05Z",
            "PwnCount": True,
            "DataClasses": ["ok", 7, "", "Y" * 500, *range(100)],
            "IsVerified": "yes",
            "IsSpamList": True,
        }
    )
    assert parsed is not None
    assert len(parsed["name"]) == 100 and parsed["title"] is None
    assert (parsed["breach_date"], parsed["added_date"]) == (None, "2020-01-02")
    assert parsed["pwn_count"] is None  # a bool is not a count
    assert parsed["data_classes"][0] == "ok" and all(len(c) <= 60 for c in parsed["data_classes"])
    assert parsed["verified"] is False and parsed["spam_list"] is True  # only a real true counts


def test_a_flood_of_breaches_is_bounded_but_counted() -> None:
    many = [{"Name": f"Breach{n}", "BreachDate": f"20{10 + n % 15}-01-01"} for n in range(300)]
    data = run(answering(many)).data
    assert len(data["breaches"]) == MAX_BREACHES and data["total"] == 200  # parsed: at most 200
    dates = [b["breach_date"] for b in data["breaches"]]
    assert dates == sorted(dates, reverse=True)


def test_everything_is_storable_as_json() -> None:
    json.dumps(run(answering(LINKEDIN), "linkedin.com").data)
