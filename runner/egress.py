"""Bounded HTTP collection with screened socket destinations and original TLS identity."""

from __future__ import annotations

import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from runner.dns import SSRFBlockedError, resolve_and_screen


class SSRFRedirectBlockedError(SSRFBlockedError):
    """A redirect leaves the allowed public HTTP destination policy."""


@dataclass
class EgressResponse:
    status_code: int
    headers: dict[str, str]  # duplicates are merged here; see ``raw_headers``
    text: str
    content: bytes
    url: str
    connected_ip: str
    redirect_history: list[tuple[str, str]] = field(default_factory=list)
    # Every header line of the final response in order, names lower-cased, duplicates kept
    # (``Set-Cookie`` cannot be merged into one value).
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    truncated: bool = False  # the body was cut at ``max_response_bytes`` (truncate_body only)


class EgressHTTPClient:
    """Use IP-literal connection URLs while retaining Host and verified TLS SNI.

    This is the HTTP transport boundary, not a substitute for runner network isolation.
    A custom transport is a dependency-injection seam for controlled offline tests.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        resolver_fn: Callable[[str], list[str]] | None = None,
        custom_transport: httpx.BaseTransport | None = None,
        max_response_bytes: int = 5 * 1024 * 1024,
        max_duration: float = 30.0,
        truncate_body: bool = False,
        verify: ssl.SSLContext | bool = True,
        connect_timeout: float | None = None,
    ) -> None:
        """``truncate_body``: cut the body at ``max_response_bytes`` and flag it, instead of
        failing. ``verify``: the trust store for HTTPS (an ``ssl.SSLContext`` lets callers use the
        operating system's store, as the TLS prober does); certificates are always verified.
        ``connect_timeout``: seconds to establish a connection (default: ``timeout``)."""
        if timeout <= 0 or max_duration <= 0 or max_response_bytes <= 0 or max_redirects < 0:
            raise ValueError("Egress limits must be positive and redirects non-negative.")
        if connect_timeout is not None and connect_timeout <= 0:
            raise ValueError("Egress limits must be positive and redirects non-negative.")
        if verify is False:
            raise ValueError("Certificate verification cannot be disabled.")
        self.connect_timeout = connect_timeout
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.resolver_fn = resolver_fn
        self._custom_transport = custom_transport
        self.max_response_bytes = max_response_bytes
        self.max_duration = max_duration
        self.truncate_body = truncate_body
        self.verify = verify

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> EgressResponse:
        current_url = url
        history: list[tuple[str, str]] = []
        deadline = time.monotonic() + self.max_duration
        supplied_headers = httpx.Headers(headers or {})
        if any(
            key in supplied_headers for key in ("authorization", "cookie", "proxy-authorization")
        ):
            raise SSRFBlockedError("Target collection must not send credentials.")
        supplied_headers.setdefault("User-Agent", "Gaprism/0.1")

        while True:
            try:
                parsed = urllib.parse.urlsplit(current_url)
                if parsed.scheme not in ("http", "https"):
                    raise SSRFBlockedError("Scheme forbidden; only HTTP(S) is supported.")
                if (
                    not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                ):
                    raise SSRFBlockedError("Missing hostname or forbidden URL credentials.")
                if parsed.port not in (None, 80, 443):
                    raise SSRFBlockedError("Target collection is restricted to ports 80 and 443.")
                original = httpx.URL(current_url)
                hostname = original.raw_host.decode("ascii")
                pinned_ip = str(resolve_and_screen(hostname, resolver_fn=self.resolver_fn)[0])
            except (ValueError, httpx.InvalidURL) as exc:
                raise SSRFBlockedError("Invalid target URL.") from exc
            except SSRFBlockedError as exc:
                if history:
                    raise SSRFRedirectBlockedError("Blocked redirect destination.") from exc
                raise

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.TimeoutException("Collection deadline exceeded.")
            request_headers = supplied_headers.copy()
            request_headers["Host"] = original.netloc.decode("ascii")
            pinned_url = original.copy_with(host=pinned_ip)
            with httpx.Client(
                timeout=httpx.Timeout(
                    min(self.timeout, remaining),
                    connect=min(self.connect_timeout or self.timeout, remaining),
                ),
                follow_redirects=False,
                trust_env=False,
                transport=self._custom_transport,
                verify=self.verify,
            ) as client:
                # httpcore uses sni_hostname for BOTH SNI and certificate hostname verification.
                with client.stream(
                    "GET",
                    pinned_url,
                    headers=request_headers,
                    extensions={"sni_hostname": hostname},
                ) as response:
                    stream = response.extensions.get("network_stream")
                    if stream is not None:
                        peer = stream.get_extra_info("server_addr")
                        if not peer or str(peer[0]) != pinned_ip:
                            raise SSRFBlockedError("Connected peer differs from screened IP.")
                    elif self._custom_transport is None:
                        raise SSRFBlockedError("Connected peer cannot be verified.")
                    if (
                        follow_redirects
                        and response.is_redirect
                        and response.headers.get("location")
                    ):
                        if len(history) >= self.max_redirects:
                            raise SSRFBlockedError("Maximum redirect limit exceeded.")
                        history.append((current_url, pinned_ip))
                        current_url = urllib.parse.urljoin(
                            current_url, response.headers["location"]
                        )
                        continue
                    body = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes(chunk_size=65536):
                        if time.monotonic() > deadline:
                            raise httpx.TimeoutException("Collection deadline exceeded.")
                        if len(body) + len(chunk) > self.max_response_bytes:
                            if not self.truncate_body:
                                raise SSRFBlockedError("Response exceeds collection byte limit.")
                            body.extend(chunk[: self.max_response_bytes - len(body)])
                            truncated = True
                            break
                        body.extend(chunk)
                    content = bytes(body)
                    return EgressResponse(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        text=content.decode(response.encoding or "utf-8", errors="replace"),
                        content=content,
                        url=current_url,
                        connected_ip=pinned_ip,
                        redirect_history=history,
                        raw_headers=list(response.headers.multi_items()),
                        truncated=truncated,
                    )
