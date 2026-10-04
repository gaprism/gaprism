"""CT discovery sources against mocked provider responses (no network)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.service.discovery.sources import CertSpotterSource, CrtShSource, CtlogsSource
from app.service.discovery.sources.base import FetchPolicy


class Recorder:
    """A mock transport that records requests and sleep calls."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []
        self._handler = handler
        self.client = httpx.Client(transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def policy(self, attempts: int = 2, max_bytes: int = 5 * 1024 * 1024) -> FetchPolicy:
        return FetchPolicy(attempts=attempts, max_bytes=max_bytes, sleep=self.sleeps.append)


def hosts_page(names: list[str], cursor: str = "") -> dict[str, Any]:
    return {
        "hosts": [
            {"host": name, "certs": 2, "first_seen": "2026-01-01T00:00:00Z"} for name in names
        ],
        "has_next": bool(cursor),
        "next_cursor": cursor,
    }


# --------------------------------------------------------------------------- ctlogs.dev


def test_ctlogs_follows_the_cursor_and_sends_the_key_only_as_a_header() -> None:
    pages = {
        None: hosts_page(["Example.com", "api.example.com"], "c1"),
        "c1": hosts_page(["www.example.com"]),
    }
    recorder = Recorder(
        lambda request: httpx.Response(200, json=pages[request.url.params.get("after")])
    )

    outcome = CtlogsSource(recorder.client, api_key="fixture-key", policy=recorder.policy()).fetch(
        "example.com"
    )

    assert (outcome.status, outcome.pages, outcome.truncated) == ("ok", 2, False)
    assert [name.name for name in outcome.names] == [
        "example.com",
        "api.example.com",
        "www.example.com",
    ]
    assert [r.url.path for r in recorder.requests] == ["/v1/hosts/example.com"] * 2
    assert recorder.requests[1].url.params["after"] == "c1"
    for request in recorder.requests:
        assert request.headers["Authorization"] == "Bearer fixture-key"
        assert "fixture-key" not in str(request.url)


def test_ctlogs_keyless_paging_limit_keeps_what_was_found_and_says_so() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("after"):
            return httpx.Response(403, json={"error": "page limit"})
        return httpx.Response(200, json=hosts_page(["a.example.com"], "c1"))

    recorder = Recorder(handler)
    outcome = CtlogsSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.truncated) == ("ok", True)
    assert [name.name for name in outcome.names] == ["a.example.com"]


def test_ctlogs_first_page_forbidden_is_unavailable_not_empty() -> None:
    recorder = Recorder(lambda request: httpx.Response(403))
    outcome = CtlogsSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code, outcome.names) == ("unavailable", "forbidden", ())


def test_ctlogs_stops_at_the_page_limit_and_flags_it() -> None:
    recorder = Recorder(
        lambda request: httpx.Response(200, json=hosts_page(["a.example.com"], "more"))
    )
    outcome = CtlogsSource(recorder.client, max_pages=3, policy=recorder.policy()).fetch(
        "example.com"
    )
    assert (outcome.status, outcome.pages, outcome.truncated) == ("ok", 3, True)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"error": "unexpected"},
        {"hosts": [], "has_next": True, "next_cursor": ""},
        {"hosts": [{"host": "example.com", "certs": "3"}], "has_next": False},
        {"hosts": [{"host": "example.com", "certs": 0}], "has_next": False},
        {
            "hosts": [{"host": "example.com", "certs": 1, "first_seen": "yesterday"}],
            "has_next": False,
        },
        {"hosts": ["example.com"], "has_next": False},
    ],
)
def test_ctlogs_malformed_payload_is_an_error_not_an_empty_success(payload: Any) -> None:
    recorder = Recorder(lambda request: httpx.Response(200, json=payload))
    outcome = CtlogsSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code, outcome.names) == ("error", "invalid_response", ())


@pytest.mark.parametrize(
    ("status", "key", "expected"),
    [
        (401, "fixture-key", ("unavailable", "invalid_key")),
        (401, "", ("unavailable", "forbidden")),
        (404, "fixture-key", ("error", "http_404")),
        (429, "fixture-key", ("unavailable", "rate_limited")),
    ],
)
def test_ctlogs_provider_errors_are_typed_and_never_echo_secrets(
    status: int, key: str, expected: tuple[str, str]
) -> None:
    recorder = Recorder(lambda request: httpx.Response(status, text="fixture-key confidential"))
    outcome = CtlogsSource(recorder.client, api_key=key, policy=recorder.policy()).fetch(
        "example.com"
    )
    assert (outcome.status, outcome.reason_code) == expected
    assert "fixture-key" not in json.dumps(outcome.summary())


def test_a_short_retry_after_is_honoured_once() -> None:
    answers = iter(
        [
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json=hosts_page(["a.example.com"])),
        ]
    )
    recorder = Recorder(lambda request: next(answers))
    outcome = CtlogsSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert outcome.status == "ok" and recorder.sleeps == [2.0]


def test_a_long_retry_after_is_not_waited_for() -> None:
    recorder = Recorder(lambda request: httpx.Response(429, headers={"Retry-After": "3600"}))
    outcome = CtlogsSource(recorder.client, policy=recorder.policy(attempts=3)).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("unavailable", "rate_limited")
    assert recorder.sleeps == [] and len(recorder.requests) == 1


def test_timeouts_and_connection_errors_are_retried_then_typed() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    slow = Recorder(timeout)
    outcome = CtlogsSource(slow.client, policy=slow.policy(attempts=3)).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")
    assert len(slow.requests) == 3 and len(slow.sleeps) == 2

    down = Recorder(refused)
    outcome = CtlogsSource(down.client, policy=down.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("error", "connection_failed")


def test_oversized_responses_are_refused_not_truncated() -> None:
    recorder = Recorder(lambda request: httpx.Response(200, content=b"x" * 5000))
    outcome = CtlogsSource(recorder.client, policy=recorder.policy(max_bytes=1000)).fetch(
        "example.com"
    )
    assert (outcome.status, outcome.reason_code) == ("error", "response_too_large")


def test_a_failure_after_the_first_page_keeps_the_partial_names_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("after"):
            return httpx.Response(500)
        return httpx.Response(200, json=hosts_page(["a.example.com"], "c1"))

    recorder = Recorder(handler)
    outcome = CtlogsSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code, outcome.truncated) == ("error", "http_500", True)
    assert [name.name for name in outcome.names] == ["a.example.com"]


# --------------------------------------------------------------------------- CertSpotter


def issuance(identifier: int, names: list[str]) -> dict[str, Any]:
    return {"id": str(identifier), "dns_names": names, "not_before": "2026-05-01T00:00:00Z"}


def test_certspotter_pages_with_after_until_the_link_header_ends() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("after") == "2":
            return httpx.Response(200, json=[issuance(3, ["Docs.Example.com"])])
        return httpx.Response(
            200,
            json=[issuance(1, ["example.com", "example.net"]), issuance(2, ["www.example.com"])],
            headers={"Link": '<https://api.certspotter.com/issuances?after=2>; rel="next"'},
        )

    recorder = Recorder(handler)
    outcome = CertSpotterSource(
        recorder.client, token="fixture-token", policy=recorder.policy()
    ).fetch("example.com")

    assert (outcome.status, outcome.pages) == ("ok", 2)
    assert [name.name for name in outcome.names] == [
        "example.com",
        "example.net",
        "www.example.com",
        "docs.example.com",
    ]
    first = recorder.requests[0]
    assert first.url.params["domain"] == "example.com"
    assert (
        first.url.params["include_subdomains"] == "true"
        and first.url.params["expand"] == "dns_names"
    )
    assert first.headers["Authorization"] == "Bearer fixture-token"
    assert "fixture-token" not in str(first.url)


def test_certspotter_empty_listing_is_a_successful_empty_result() -> None:
    recorder = Recorder(lambda request: httpx.Response(200, json=[]))
    outcome = CertSpotterSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.names, outcome.pages) == ("ok", (), 0)


def test_certspotter_rate_limit_is_unavailable() -> None:
    recorder = Recorder(lambda request: httpx.Response(429))
    outcome = CertSpotterSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("unavailable", "rate_limited")


def test_certspotter_stalled_pagination_is_detected() -> None:
    link = {"Link": '<https://api.certspotter.com/issuances?after=1>; rel="next"'}
    recorder = Recorder(
        lambda request: httpx.Response(200, json=[issuance(1, ["a.example.com"])], headers=link)
    )
    outcome = CertSpotterSource(recorder.client, max_pages=10, policy=recorder.policy()).fetch(
        "example.com"
    )
    assert (outcome.status, outcome.reason_code, outcome.truncated) == (
        "error",
        "pagination_stalled",
        True,
    )
    assert len(recorder.requests) == 2


@pytest.mark.parametrize(
    "payload", [{}, {"issuances": []}, ["x"], [{"id": 1}], [{"id": 1, "dns_names": [5]}]]
)
def test_certspotter_malformed_payload_is_an_error(payload: Any) -> None:
    recorder = Recorder(lambda request: httpx.Response(200, json=payload))
    outcome = CertSpotterSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("error", "invalid_response")


# --------------------------------------------------------------------------- crt.sh


def test_crtsh_splits_name_value_and_encodes_the_wildcard_query() -> None:
    rows = [
        {"name_value": "Example.com\nwww.example.com", "not_before": "2026-03-01T00:00:00"},
        {"name_value": "*.example.com", "not_before": "2026-04-01T00:00:00"},
    ]
    recorder = Recorder(lambda request: httpx.Response(200, json=rows))
    outcome = CrtShSource(recorder.client, policy=recorder.policy()).fetch("example.com")

    assert outcome.status == "ok"
    assert [name.name for name in outcome.names] == [
        "example.com",
        "www.example.com",
        "*.example.com",
    ]
    assert (
        outcome.names[0].first_seen is not None and outcome.names[0].first_seen.tzinfo is not None
    )
    request = recorder.requests[0]
    assert request.url.params["q"] == "%.example.com" and "%25.example.com" in str(request.url)


def test_crtsh_retries_a_flaky_gateway_then_succeeds() -> None:
    answers = iter([httpx.Response(502), httpx.Response(502), httpx.Response(200, json=[])])
    recorder = Recorder(lambda request: next(answers))
    outcome = CrtShSource(recorder.client, policy=recorder.policy(attempts=3)).fetch("example.com")
    assert outcome.status == "ok" and len(recorder.requests) == 3 and len(recorder.sleeps) == 2


def test_crtsh_gives_up_with_a_typed_error_when_the_gateway_stays_down() -> None:
    recorder = Recorder(lambda request: httpx.Response(502, text="<html>Bad Gateway</html>"))
    outcome = CrtShSource(recorder.client, policy=recorder.policy(attempts=3)).fetch("example.com")
    assert (outcome.status, outcome.reason_code) == ("error", "http_502")
    assert len(recorder.requests) == 3


def test_crtsh_html_with_status_200_is_an_error_not_an_empty_result() -> None:
    recorder = Recorder(lambda request: httpx.Response(200, text="<html>overloaded</html>"))
    outcome = CrtShSource(recorder.client, policy=recorder.policy()).fetch("example.com")
    assert (outcome.status, outcome.reason_code, outcome.names) == ("error", "invalid_response", ())


def test_backoff_delays_are_bounded_and_jittered() -> None:
    recorder = Recorder(lambda request: httpx.Response(503))
    CrtShSource(recorder.client, policy=recorder.policy(attempts=6)).fetch("example.com")
    assert len(recorder.sleeps) == 5
    assert all(0.0 < delay <= 8.0 for delay in recorder.sleeps)
