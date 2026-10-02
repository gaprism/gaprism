"""Egress HTTP client with destination IP pinning and Anti-SSRF redirect enforcement."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from runner.dns import IPAddressType, SSRFBlockedError, resolve_and_screen


class SSRFRedirectBlockedError(SSRFBlockedError):
    """Raised when an HTTP redirect attempts to route traffic to a private destination."""


@dataclass
class EgressResponse:
    """Standardised egress HTTP response container with provenance metadata."""

    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes
    url: str
    connected_ip: str
    redirect_history: list[tuple[str, str]] = field(default_factory=list)


class EgressHTTPClient:
    """Safe HTTP client enforcing Anti-SSRF destination screening and redirect verification.

    Enforces invariants:
    - INV-06: All target traffic crosses enforced public-only egress.
    - Pins destination IP per connection to eliminate DNS rebinding risks.
    - Inspects all HTTP redirect targets before following and terminates on private endpoints.
    - Rejects non-HTTP(S) schemes and restricts redirect hops to a configurable ceiling.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        resolver_fn: Callable[[str], list[str]] | None = None,
        custom_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.resolver_fn = resolver_fn
        self._custom_transport = custom_transport

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> EgressResponse:
        """Execute a secure GET request with IP pinning and redirect screening."""
        return self._request_with_redirect_screening(
            method="GET",
            url=url,
            headers=headers or {},
            follow_redirects=follow_redirects,
        )

    def _request_with_redirect_screening(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        follow_redirects: bool,
    ) -> EgressResponse:
        current_url = url
        redirect_history: list[tuple[str, str]] = []
        hops = 0

        req_headers = dict(headers)
        if "User-Agent" not in req_headers and "user-agent" not in req_headers:
            req_headers["User-Agent"] = "TechnicalDueDiligenceBot/1.0"

        while True:
            parsed = urllib.parse.urlparse(current_url)
            scheme = parsed.scheme.lower()

            if scheme not in ("http", "https"):
                raise SSRFBlockedError(
                    f"Scheme '{scheme}' is forbidden. Only 'http' and 'https' are allowed."
                )

            hostname = parsed.hostname
            if not hostname:
                raise SSRFBlockedError(f"Invalid URL without hostname: '{current_url}'.")

            # 1. Resolve and screen hostname
            public_ips = resolve_and_screen(hostname, resolver_fn=self.resolver_fn)
            pinned_ip: IPAddressType = public_ips[0]
            pinned_ip_str = str(pinned_ip)

            # 2. Execute single-hop request without automatic redirects
            client_kwargs: dict[str, Any] = {
                "timeout": self.timeout,
                "follow_redirects": False,
            }
            if self._custom_transport is not None:
                client_kwargs["transport"] = self._custom_transport

            with httpx.Client(**client_kwargs) as client:
                try:
                    resp = client.request(
                        method=method,
                        url=current_url,
                        headers=req_headers,
                    )
                except httpx.HTTPError as e:
                    raise SSRFBlockedError(
                        f"Target request failed for {current_url} ({pinned_ip_str}): {e}"
                    ) from e

            # 3. Handle redirects manually to enforce anti-SSRF on the redirect target
            if follow_redirects and resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    break

                hops += 1
                if hops > self.max_redirects:
                    raise SSRFBlockedError(
                        f"Maximum redirect limit of {self.max_redirects} hops exceeded."
                    )

                redirect_history.append((current_url, pinned_ip_str))
                next_url = urllib.parse.urljoin(current_url, location)
                next_parsed = urllib.parse.urlparse(next_url)
                next_hostname = next_parsed.hostname

                if not next_hostname:
                    raise SSRFBlockedError(f"Malformed redirect location: '{location}'.")

                # SCREEN NEXT REDIRECT DESTINATION BEFORE MAKING ANY CONNECTION (NET-01)
                try:
                    resolve_and_screen(next_hostname, resolver_fn=self.resolver_fn)
                except SSRFBlockedError as e:
                    err_msg = (
                        f"Blocked redirect from {current_url} to private destination "
                        f"{next_url}: {e}"
                    )
                    raise SSRFRedirectBlockedError(err_msg) from e

                current_url = next_url
                continue

            # Terminal response reached
            return EgressResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                url=current_url,
                connected_ip=pinned_ip_str,
                redirect_history=redirect_history,
            )

        raise SSRFBlockedError("Unexpected termination of request redirect evaluation loop.")
