"""The HTTP check through the real egress client over a scripted transport (no network)."""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.http import (
    MAX_BODY_BYTES,
    MAX_COOKIES,
    MAX_HEADERS,
    MAX_REDIRECTS,
    HttpCheck,
    classify_error,
    parse_set_cookie,
)
from runner.dns import DNSResolutionError, SSRFBlockedError
from runner.egress import EgressHTTPClient

HOST = "www.example.com"
PUBLIC_IP = "93.184.216.34"
CONFIG: dict[str, Any] = {"USER_AGENT": "TestAgent/1.0"}
DNS_OK = CheckOutcome("ok", data={"addresses": [PUBLIC_IP], "blocked": []})

Reply = httpx.Response | Exception | Callable[[httpx.Request], httpx.Response]


class Site:
    """Scripted web servers keyed by ``(scheme, host, path)``; records every request."""

    def __init__(self, routes: dict[tuple[str, str, str], Reply]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.url.scheme, request.headers["host"], request.url.path)
        reply = self.routes.get(key, httpx.Response(404, text="not scripted"))
        if isinstance(reply, Exception):
            raise reply
        return reply(request) if callable(reply) else reply


def run(
    site: Site,
    names: dict[str, list[str]] | None = None,
    previous: dict[str, CheckOutcome] | None = None,
    host: str = HOST,
) -> CheckOutcome:
    def factory(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            resolver_fn=resolver_fn,
            custom_transport=httpx.MockTransport(site),
            max_response_bytes=MAX_BODY_BYTES,
            truncate_body=True,
            max_redirects=0,
        )

    table = names or {}
    check = HttpCheck(
        client_factory=factory, name_resolver=lambda config, name: table.get(name, [])
    )
    ctx = CheckContext(
        domain="example.com",
        hostname=host,
        config=CONFIG,
        http=httpx.Client(),
        previous={"dns": DNS_OK} if previous is None else previous,
    )
    return check.run(ctx)


def page(
    status: int = 200, headers: list[tuple[str, str]] | None = None, body: str = "<html></html>"
) -> httpx.Response:
    return httpx.Response(
        status, headers=[("content-type", "text/html; charset=utf-8"), *(headers or [])], text=body
    )


def redirect(location: str, status: int = 301) -> httpx.Response:
    return httpx.Response(status, headers={"Location": location})


def refused() -> Exception:
    error = httpx.ConnectError("connect failed")
    error.__cause__ = ConnectionRefusedError("refused")
    return error


# ------------------------------------------------------------------------------ the facts


def test_a_healthy_site_reports_status_headers_cookies_and_the_http_redirect() -> None:
    site = Site(
        {
            ("https", HOST, "/"): page(
                headers=[
                    ("Server", "nginx"),
                    ("X-Powered-By", "PHP/8.3.1"),
                    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Set-Cookie", "sid=SECRET-VALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "tracker=1; Max-Age=3600"),
                ],
                body="<html><head><title>  Example &amp;\n Co </title></head></html>",
            ),
            ("http", HOST, "/"): redirect(f"https://{HOST}/"),
        }
    )
    outcome = run(site)

    assert (outcome.status, outcome.source) == ("ok", "http-probe")
    data = outcome.data
    assert (data["scheme"], data["status"], data["final_url"]) == ("https", 200, f"https://{HOST}/")
    assert data["connected_ip"] == PUBLIC_IP and data["redirects"] == []
    assert (data["server"], data["powered_by"]) == ("nginx", "PHP/8.3.1")
    assert data["security_headers"]["strict-transport-security"].startswith("max-age=31536000")
    assert data["security_headers"]["x-content-type-options"] == "nosniff"
    assert data["security_headers"]["content-security-policy"] is None  # absent is explicit
    assert data["html_title"] == "Example & Co"
    assert data["http_port80"] == {
        "status": 301,
        "error": None,
        "location": f"https://{HOST}/",
        "redirects_to_https": True,
        "ip": PUBLIC_IP,
    }
    assert data["https_error"] is None and data["https_final"] is True
    sid, tracker = data["cookies"]
    assert (sid["name"], sid["secure"], sid["httponly"], sid["samesite"]) == (
        "sid",
        True,
        True,
        "lax",
    )
    assert (tracker["secure"], tracker["httponly"], tracker["session"], tracker["max_age"]) == (
        False,
        False,
        False,
        3600,
    )
    assert "SECRET-VALUE" not in str(data)  # cookie values are never stored
    assert all(h["name"] != "set-cookie" for h in data["headers"])


def test_the_first_page_is_read_for_what_it_names_and_its_text_is_not_kept() -> None:
    body = (
        '<html><head><meta name="generator" content="WordPress 6.4.2">'
        '<script src="https://cdn.example.net/app.js?ver=1.2&token=SECRET"></script></head>'
        "<body>Private page text</body></html>"
    )
    site = Site({("https", HOST, "/"): page(body=body), ("http", HOST, "/"): page()})
    data = run(site).data
    assert data["page"]["generator"] == ["WordPress 6.4.2"]
    assert data["page"]["resources"] == [
        {"kind": "script", "host": "cdn.example.net", "path": "/app.js", "version": "1.2"}
    ]
    assert data["page"]["truncated"] is False
    stored = json.dumps(data)
    assert "SECRET" not in stored and "Private page text" not in stored


def test_a_response_that_is_not_html_has_no_page_facts() -> None:
    document = httpx.Response(
        200,
        headers={"content-type": "application/json"},
        text='{"html": "<script src=https://x.example/a.js></script>"}',
    )
    site = Site({("https", HOST, "/"): document, ("http", HOST, "/"): page()})
    assert run(site).data["page"] is None


def test_a_page_that_is_cut_is_read_as_far_as_it_goes_and_says_so() -> None:
    body = '<script src="https://cdn.example.net/a.js"></script>' + "<p>x</p>" * (
        MAX_BODY_BYTES // 8
    )
    site = Site({("https", HOST, "/"): page(body=body), ("http", HOST, "/"): page()})
    data = run(site).data
    assert data["body_truncated"] is True
    assert data["page"]["resources"][0]["host"] == "cdn.example.net"
    assert data["page"]["truncated"] is True  # more tags than are read


def test_requests_go_to_the_screened_address_with_our_identity_and_no_credentials() -> None:
    site = Site({("https", HOST, "/"): page(), ("http", HOST, "/"): page()})
    run(site)
    assert {request.url.host for request in site.requests} == {PUBLIC_IP}  # never re-resolved
    for request in site.requests:
        assert request.headers["user-agent"] == "TestAgent/1.0"
        assert request.headers["host"] == HOST
        assert "authorization" not in request.headers and "cookie" not in request.headers


def test_a_redirect_chain_is_recorded_hop_by_hop() -> None:
    site = Site(
        {
            ("https", HOST, "/"): redirect(f"https://{HOST}/en/", 302),
            ("https", HOST, "/en/"): redirect("/en/home", 307),
            ("https", HOST, "/en/home"): page(headers=[("Server", "Apache")]),
            ("http", HOST, "/"): page(),
        }
    )
    data = run(site).data
    assert [(hop["status"], hop["url"], hop["location"]) for hop in data["redirects"]] == [
        (302, f"https://{HOST}/", f"https://{HOST}/en/"),
        (307, f"https://{HOST}/en/", "/en/home"),
    ]
    assert data["final_url"] == f"https://{HOST}/en/home" and data["status"] == 200
    assert data["redirect_incomplete"] is None and data["server"] == "Apache"
    assert data["http_port80"]["redirects_to_https"] is False  # port 80 serves, no redirect


def test_plain_http_that_does_not_redirect_is_reported_as_such() -> None:
    site = Site({("https", HOST, "/"): page(), ("http", HOST, "/"): page(body="clear text")})
    assert run(site).data["http_port80"] | {"ip": None} == {
        "status": 200,
        "error": None,
        "location": None,
        "redirects_to_https": False,
        "ip": None,
    }


def test_a_downgrade_and_a_foreign_final_host_are_flagged() -> None:
    site = Site(
        {
            ("https", HOST, "/"): redirect("http://other.example.net/landing"),
            ("http", "other.example.net", "/landing"): page(),
            ("http", HOST, "/"): page(),
        }
    )
    data = run(site, names={"other.example.net": ["93.184.216.99"]}).data
    assert data["downgrade"] is True and data["cross_host_final"] is True
    assert data["https_final"] is False and data["final_url"] == "http://other.example.net/landing"


# ------------------------------------------------------------------------------ fallbacks


def test_when_https_is_refused_plain_http_is_the_answer() -> None:
    site = Site(
        {("https", HOST, "/"): refused(), ("http", HOST, "/"): page(headers=[("Server", "x")])}
    )
    outcome = run(site)
    assert outcome.status == "ok"
    assert (outcome.data["scheme"], outcome.data["https_error"]) == ("http", "refused")
    assert outcome.data["server"] == "x" and outcome.data["https_final"] is False


def test_a_broken_certificate_keeps_the_port_80_redirect_as_evidence() -> None:
    bad_certificate = httpx.ConnectError("certificate verify failed")
    bad_certificate.__cause__ = ssl.SSLCertVerificationError("expired")
    site = Site(
        {("https", HOST, "/"): bad_certificate, ("http", HOST, "/"): redirect(f"https://{HOST}/")}
    )
    outcome = run(site)

    assert outcome.status == "ok"  # the redirect response was collected
    data = outcome.data
    assert data["https_error"] == "tls_verification_failed"
    assert data["status"] == 301 and data["scheme"] == "http"
    assert data["redirect_incomplete"] == {
        "stopped_at": f"https://{HOST}/",
        "reason": "tls_verification_failed",
    }
    assert data["http_port80"]["redirects_to_https"] is True


def test_no_web_server_at_all_is_no_data_not_an_error() -> None:
    outcome = run(Site({("https", HOST, "/"): refused(), ("http", HOST, "/"): refused()}))
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_web_server")
    assert outcome.data["https_error"] == "refused"
    assert outcome.data["http_port80"]["error"] == "refused"


def test_a_timeout_is_an_error_with_its_reason() -> None:
    site = Site(
        {("https", HOST, "/"): httpx.ConnectTimeout("slow"), ("http", HOST, "/"): refused()}
    )
    outcome = run(site)
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")


# ------------------------------------------------------------------------------ the gate


def test_a_redirect_into_private_space_is_blocked_and_the_evidence_kept() -> None:
    site = Site(
        {
            ("https", HOST, "/"): redirect("https://internal.example.net/admin"),
            ("http", HOST, "/"): page(),
        }
    )
    outcome = run(site, names={"internal.example.net": ["10.0.0.7"]})
    assert outcome.status == "ok"
    data = outcome.data
    assert data["status"] == 301 and data["redirects"][0]["location"].endswith("/admin")
    assert data["redirect_incomplete"] == {
        "stopped_at": "https://internal.example.net/admin",
        "reason": "blocked_destination",
    }
    assert all(request.url.host != "10.0.0.7" for request in site.requests)  # never connected


def test_a_redirect_to_another_port_is_not_followed() -> None:
    site = Site(
        {("https", HOST, "/"): redirect(f"https://{HOST}:8443/"), ("http", HOST, "/"): page()}
    )
    data = run(site).data
    assert data["redirect_incomplete"]["reason"] == "blocked_destination"


def test_a_redirect_loop_stops_at_the_limit() -> None:
    site = Site({("https", HOST, "/"): redirect(f"https://{HOST}/"), ("http", HOST, "/"): page()})
    data = run(site).data
    assert data["redirect_incomplete"]["reason"] == "too_many_redirects"
    assert len(data["redirects"]) == MAX_REDIRECTS + 1
    assert len([r for r in site.requests if r.url.scheme == "https"]) == MAX_REDIRECTS + 1


# ------------------------------------------------------------------------------ bounds


def test_a_huge_body_is_cut_and_flagged_not_an_error() -> None:
    site = Site(
        {
            ("https", HOST, "/"): page(body="x" * (MAX_BODY_BYTES + 1000)),
            ("http", HOST, "/"): page(),
        }
    )
    data = run(site).data
    assert data["body_truncated"] is True and data["body_bytes"] == MAX_BODY_BYTES


def test_headers_cookies_and_values_are_bounded() -> None:
    many = [(f"X-Header-{n}", "v" * 900) for n in range(MAX_HEADERS + 40)]
    cookies = [("Set-Cookie", f"c{n}=1") for n in range(MAX_COOKIES + 10)]
    site = Site({("https", HOST, "/"): page(headers=many + cookies), ("http", HOST, "/"): page()})
    data = run(site).data
    assert len(data["headers"]) == MAX_HEADERS and len(data["headers"][0]["value"]) <= 500
    assert len(data["cookies"]) == MAX_COOKIES


# ------------------------------------------------------------------------------ prerequisites


def test_without_a_usable_address_the_check_is_skipped_and_nothing_is_requested() -> None:
    site = Site({})
    blocked = {"addresses": [], "blocked": [{"ip": "10.0.0.5", "reason": "private"}]}
    outcome = run(site, previous={"dns": CheckOutcome("ok", data=blocked)})
    assert (outcome.status, outcome.reason_code) == ("skipped", "no_public_address")
    assert site.requests == []


# ------------------------------------------------------------------------------ helpers


def test_cookie_flags_prefixes_and_garbage() -> None:
    cookie = parse_set_cookie(
        "__Host-id=abc; Path=/; Secure; HttpOnly; SameSite=Strict; "
        "Expires=Wed, 01 Jan 2031 00:00:00 GMT"
    )
    assert cookie is not None
    assert (cookie["prefix"], cookie["samesite"], cookie["session"]) == ("host", "strict", False)
    assert cookie["expires"] == "Wed, 01 Jan 2031 00:00:00 GMT" and cookie["path"] == "/"
    assert parse_set_cookie("__Secure-x=1; Secure")["prefix"] == "secure"  # type: ignore[index]
    assert parse_set_cookie("plain=1")["session"] is True  # type: ignore[index]
    assert parse_set_cookie("Secure; HttpOnly") is None  # attributes only: no name=value pair
    assert parse_set_cookie("=value") is None
    assert parse_set_cookie("a=1; Max-Age=forever")["max_age"] is None  # type: ignore[index]


def test_a_title_only_comes_from_html() -> None:
    site = Site(
        {
            ("https", HOST, "/"): httpx.Response(
                200, headers={"Content-Type": "application/json"}, text="<title>nope</title>"
            ),
            ("http", HOST, "/"): page(),
        }
    )
    assert run(site).data["html_title"] is None


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (DNSResolutionError("no such host"), "dns_failed"),
        (SSRFBlockedError("private"), "blocked_destination"),
        (httpx.ConnectTimeout("t"), "timeout"),
        (httpx.ReadTimeout("t"), "timeout"),
        (httpx.ConnectError("x"), "connection_failed"),
        (httpx.ReadError("x"), "protocol_error"),
        (httpx.InvalidURL("x"), "http_error"),
    ],
)
def test_errors_become_stable_codes(error: BaseException, code: str) -> None:
    assert classify_error(error) == code


def test_connect_errors_are_told_apart_by_their_cause() -> None:
    def chained(cause: BaseException) -> httpx.ConnectError:
        error = httpx.ConnectError("x")
        error.__cause__ = cause
        return error

    assert classify_error(chained(ssl.SSLCertVerificationError("bad"))) == "tls_verification_failed"
    assert classify_error(chained(ssl.SSLError("handshake"))) == "tls_error"
    assert classify_error(chained(ConnectionRefusedError())) == "refused"
