"""HTTP: what a host answers on ports 443 and 80 - status, redirects, security headers, cookies.

Every request goes through ``runner.egress`` (screened addresses, IP-pinned connections, SNI,
bounded time and size). Redirects are followed one hop at a time here, so a hop that is blocked
or fails keeps the evidence gathered so far instead of losing it. The connection goes to the
addresses the DNS check found, so nothing is resolved twice. Cookie *values* are never stored:
only names and flags.
"""

from __future__ import annotations

import functools
import html
import itertools
import re
import ssl
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.dns import SHARED_RESOLVERS, lookup_addresses
from runner.dns import DNSResolutionError, SSRFBlockedError
from runner.egress import EgressHTTPClient, EgressResponse

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024
TITLE_SCAN_CHARS = 64 * 1024
MAX_HEADERS = 60
MAX_VALUE = 500
MAX_COOKIES = 50
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
REQUEST_HEADERS = {"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"}
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

ClientFactory = Callable[[Mapping[str, Any], Callable[[str], list[str]]], EgressHTTPClient]
NameResolver = Callable[[Mapping[str, Any], str], list[str]]


@functools.lru_cache(maxsize=1)
def _trust_store() -> ssl.SSLContext:
    """The operating system's CA store, the same one the TLS prober uses."""
    return ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)


def _default_client(
    config: Mapping[str, Any], resolver_fn: Callable[[str], list[str]]
) -> EgressHTTPClient:
    read = float(config.get("EGRESS_READ_TIMEOUT_SEC", 20.0))
    connect = float(config.get("EGRESS_CONNECT_TIMEOUT_SEC", 10.0))
    return EgressHTTPClient(
        timeout=read,
        connect_timeout=connect,
        max_redirects=0,  # followed here, hop by hop
        resolver_fn=resolver_fn,
        max_response_bytes=MAX_BODY_BYTES,
        max_duration=read + connect,
        truncate_body=True,
        verify=_trust_store(),
    )


def _default_names(config: Mapping[str, Any], name: str) -> list[str]:
    lifetime = float(config.get("DNS_TIMEOUT_SECONDS", 5.0))
    return lookup_addresses(SHARED_RESOLVERS.get(config), name, lifetime)


# ------------------------------------------------------------------------------ requests


@dataclass
class _Fetch:
    response: EgressResponse | None = None
    error: str | None = None


@dataclass
class _Trace:
    """A chain of requests: every response in order, and how the chain ended."""

    responses: list[EgressResponse] = field(default_factory=list)
    error: str | None = None  # why the next request could not be made or answered
    stopped_url: str | None = None  # the request that failed (the first one, or a later hop)
    limit_reached: bool = False
    elapsed_ms: int = 0

    @property
    def final(self) -> EgressResponse | None:
        return self.responses[-1] if self.responses else None


def _causes(exc: BaseException) -> Iterator[BaseException]:
    current: BaseException | None = exc
    for _ in range(8):
        if current is None:
            return
        yield current
        current = current.__cause__ or current.__context__


def classify_error(exc: BaseException) -> str:
    """A stable code for a failed request; never the exception text (it may hold internals)."""
    if isinstance(exc, DNSResolutionError):
        return "dns_failed"
    if isinstance(exc, SSRFBlockedError):
        return "blocked_destination"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        for cause in _causes(exc):
            if isinstance(cause, ssl.SSLCertVerificationError):
                return "tls_verification_failed"
            if isinstance(cause, ssl.SSLError):
                return "tls_error"
            if isinstance(cause, ConnectionRefusedError):
                return "refused"
        return "connection_failed"
    if isinstance(exc, httpx.TransportError):
        return "protocol_error"
    return "http_error"


def _fetch(client: EgressHTTPClient, url: str, headers: dict[str, str]) -> _Fetch:
    try:
        return _Fetch(response=client.get(url, headers=headers, follow_redirects=False))
    except (SSRFBlockedError, DNSResolutionError, httpx.HTTPError) as exc:
        return _Fetch(error=classify_error(exc))


def redirect_target(response: EgressResponse) -> str | None:
    """Where a redirect response sends the client (absolute), or ``None`` if it is not one."""
    location = response.headers.get("location")
    if response.status_code in REDIRECT_STATUSES and location:
        return urllib.parse.urljoin(response.url, location)
    return None


def _follow(client: EgressHTTPClient, url: str, headers: dict[str, str]) -> _Trace:
    """Request ``url`` and follow its redirects (at most ``MAX_REDIRECTS``), one screened hop at
    a time."""
    started = time.monotonic()
    trace = _Trace()
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        fetch = _fetch(client, current, headers)
        if fetch.response is None:
            trace.error, trace.stopped_url = fetch.error, current
            break
        trace.responses.append(fetch.response)
        target = redirect_target(fetch.response)
        if target is None:
            break
        if hop == MAX_REDIRECTS:
            trace.limit_reached, trace.stopped_url = True, target
            break
        current = target
    trace.elapsed_ms = int((time.monotonic() - started) * 1000)
    return trace


# ------------------------------------------------------------------------------ reading responses


def _first(raw: list[tuple[str, str]], name: str) -> str | None:
    for header, value in raw:
        if header == name:
            return value[:MAX_VALUE]
    return None


def _joined(raw: list[tuple[str, str]], name: str) -> str | None:
    values = [value for header, value in raw if header == name]
    return ", ".join(values)[: MAX_VALUE * 2] if values else None


def parse_set_cookie(line: str) -> dict[str, Any] | None:
    """Name and flags of one ``Set-Cookie`` header. The value is deliberately dropped."""
    parts = [part.strip() for part in line.split(";")]
    name, separator, _value = parts[0].partition("=")
    name = name.strip()
    if not separator or not name:
        return None
    cookie: dict[str, Any] = {
        "name": name[:100],
        "secure": False,
        "httponly": False,
        "samesite": None,
        "path": None,
        "domain": None,
        "max_age": None,
        "expires": None,
        "prefix": "host"
        if name.startswith("__Host-")
        else "secure"
        if name.startswith("__Secure-")
        else None,
    }
    for attribute in parts[1:]:
        key, _, value = attribute.partition("=")
        key, value = key.strip().lower(), value.strip()
        if key == "secure":
            cookie["secure"] = True
        elif key == "httponly":
            cookie["httponly"] = True
        elif key == "samesite":
            cookie["samesite"] = value.lower()[:10] or None
        elif key == "path":
            cookie["path"] = value[:200] or None
        elif key == "domain":
            cookie["domain"] = value.lower()[:255] or None
        elif key == "max-age":
            cookie["max_age"] = int(value) if re.fullmatch(r"-?\d{1,12}", value) else None
        elif key == "expires":
            cookie["expires"] = value[:64] or None
    cookie["session"] = cookie["max_age"] is None and cookie["expires"] is None
    return cookie


def _cookies(responses: list[EgressResponse]) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for response in responses:
        for header, value in response.raw_headers:
            if header == "set-cookie" and len(cookies) < MAX_COOKIES:
                cookie = parse_set_cookie(value)
                if cookie is not None:
                    cookies.append(cookie)
    return cookies


def _title(response: EgressResponse) -> str | None:
    content_type = _first(response.raw_headers, "content-type") or ""
    if "html" not in content_type.lower():
        return None
    match = _TITLE.search(response.text[:TITLE_SCAN_CHARS])
    if match is None:
        return None
    return " ".join(html.unescape(match.group(1)).split())[:200] or None


def _hop(response: EgressResponse) -> dict[str, Any]:
    return {
        "url": response.url,
        "status": response.status_code,
        "location": (response.headers.get("location") or "")[:MAX_VALUE],
        "ip": response.connected_ip,
    }


def _port80(probe: _Fetch) -> dict[str, Any]:
    """What plain HTTP does: does it send visitors to HTTPS, or serve in clear text?"""
    if probe.response is None:
        return {"status": None, "error": probe.error, "redirects_to_https": None}
    target = redirect_target(probe.response)
    return {
        "status": probe.response.status_code,
        "error": None,
        "location": (probe.response.headers.get("location") or "")[:MAX_VALUE] or None,
        "redirects_to_https": bool(target and target.startswith("https://")),
        "ip": probe.response.connected_ip,
    }


class HttpCheck:
    """Request ``https://host/`` and ``http://host/`` and describe what comes back."""

    key = "http"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        name_resolver: NameResolver | None = None,
    ) -> None:
        self._client_factory = client_factory or _default_client
        self._names = name_resolver or _default_names

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        addresses = [str(ip) for ip in dns.data.get("addresses", [])] if dns else []
        if not addresses:
            blocked = dns.data.get("blocked", []) if dns else []
            return CheckOutcome("skipped", "no_public_address", {"blocked": blocked})
        host = (ctx.hostname or "").lower().rstrip(".")

        def resolve(name: str) -> list[str]:
            # The host itself uses the addresses DNS already screened; other names (redirect
            # targets) are looked up the same way and then screened again by the gate.
            name = name.lower().rstrip(".")
            return list(addresses) if name == host else self._names(ctx.config, name)

        client = self._client_factory(ctx.config, resolve)
        headers = {
            **REQUEST_HEADERS,
            "User-Agent": str(ctx.config.get("USER_AGENT", "WebDueDiligence")),
        }

        https = _follow(client, f"https://{host}/", headers)
        port80 = _fetch(client, f"http://{host}/", headers)
        if https.responses:
            main, scheme = https, "https"
        elif port80.response is not None and redirect_target(port80.response) is None:
            main, scheme = _Trace(responses=[port80.response]), "http"  # plain HTTP, no redirect
        elif port80.response is not None:
            main, scheme = _follow(client, f"http://{host}/", headers), "http"
        else:
            main, scheme = _Trace(error=port80.error), "http"

        final = main.final
        if final is None:
            errors = {https.error, port80.error}
            if errors == {"refused"}:
                return CheckOutcome(
                    "no_data", "no_web_server", self._base(https, port80), "http-probe"
                )
            reason = next((e for e in (https.error, port80.error) if e and e != "refused"), None)
            return CheckOutcome(
                "error", reason or "no_response", self._base(https, port80), "http-probe"
            )

        hops = [response for response in main.responses if redirect_target(response)]
        complete = redirect_target(final) is None
        raw = final.raw_headers
        urls = [response.url for response in main.responses]
        data: dict[str, Any] = {
            **self._base(https, port80),
            "scheme": scheme,
            "final_url": final.url,
            "status": final.status_code,
            "connected_ip": final.connected_ip,
            "redirects": [_hop(response) for response in hops],
            "redirect_incomplete": None
            if complete
            else {
                "stopped_at": (main.stopped_url or redirect_target(final) or "")[:MAX_VALUE],
                "reason": "too_many_redirects" if main.limit_reached else main.error,
            },
            "https_final": final.url.startswith("https://"),
            "downgrade": any(
                earlier.startswith("https://") and later.startswith("http://")
                for earlier, later in itertools.pairwise(urls)
            ),
            "cross_host_final": (urllib.parse.urlsplit(final.url).hostname or "") != host,
            "server": _first(raw, "server"),
            "powered_by": _first(raw, "x-powered-by"),
            "content_type": _first(raw, "content-type"),
            "security_headers": {name: _joined(raw, name) for name in SECURITY_HEADERS},
            "headers": [
                {"name": name[:100], "value": value[:MAX_VALUE]}
                for name, value in raw
                if name != "set-cookie"
            ][:MAX_HEADERS],
            "cookies": _cookies(main.responses),
            "html_title": _title(final),
            "body_bytes": len(final.content),
            "body_truncated": final.truncated,
            "timing_ms": main.elapsed_ms,
        }
        return CheckOutcome("ok", data=data, source="http-probe")

    @staticmethod
    def _base(https: _Trace, port80: _Fetch) -> dict[str, Any]:
        """What both schemes said, whether or not a page came back."""
        return {
            "https_error": https.error if not https.responses else None,
            "http_port80": _port80(port80),
        }
