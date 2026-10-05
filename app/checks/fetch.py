"""Fetch one small document through the egress gate (security.txt, MTA-STS policy, RDAP, ...).

The host name is resolved with the configured resolvers, the connection goes to a screened public
address (IP-pinned, certificate verified against the original name), size and time are bounded
and failures come back as stable codes, never as exception text. Redirects are followed one
screened hop at a time (``MAX_HOPS``), so a document that moves is still found and the chain is
reported.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.checks.dns import SHARED_RESOLVERS, lookup_addresses
from app.checks.http import classify_error, redirect_target, trust_store
from runner.dns import DNSResolutionError, SSRFBlockedError
from runner.egress import EgressHTTPClient, EgressResponse

MAX_DOCUMENT_BYTES = 64 * 1024
MAX_HOPS = 3
ClientFactory = Callable[[Mapping[str, Any], Callable[[str], list[str]]], EgressHTTPClient]
NameResolver = Callable[[Mapping[str, Any], str], list[str]]


def default_client(
    config: Mapping[str, Any],
    resolver_fn: Callable[[str], list[str]],
    max_bytes: int = MAX_DOCUMENT_BYTES,
) -> EgressHTTPClient:
    read = float(config.get("EGRESS_READ_TIMEOUT_SEC", 20.0))
    connect = float(config.get("EGRESS_CONNECT_TIMEOUT_SEC", 10.0))
    return EgressHTTPClient(
        timeout=read,
        connect_timeout=connect,
        max_redirects=0,  # followed here, hop by hop
        resolver_fn=resolver_fn,
        max_response_bytes=max_bytes,
        max_duration=read + connect,
        truncate_body=True,
        verify=trust_store(),
    )


def default_names(config: Mapping[str, Any], name: str) -> list[str]:
    lifetime = float(config.get("DNS_TIMEOUT_SECONDS", 5.0))
    return lookup_addresses(SHARED_RESOLVERS.get(config), name, lifetime)


@dataclass
class Document:
    """What came back for a URL: the final response (or why there is none) and the hops taken."""

    response: EgressResponse | None = None
    error: str | None = None
    url: str = ""  # the URL that was asked for last (the final one, or the one that failed)
    hops: list[str] = field(default_factory=list)  # URLs that redirected, in order
    redirect_limit: bool = False


def fetch_document(
    client: EgressHTTPClient, url: str, headers: dict[str, str] | None = None
) -> Document:
    """GET ``url``, following up to ``MAX_HOPS`` redirects; failures become ``Document.error``."""
    document = Document(url=url)
    current = url
    for hop in range(MAX_HOPS + 1):
        document.url = current
        try:
            response = client.get(current, headers=headers or {}, follow_redirects=False)
        except (SSRFBlockedError, DNSResolutionError, httpx.HTTPError) as exc:
            document.response, document.error = None, classify_error(exc)
            return document
        target = redirect_target(response)
        if target is None:
            document.response = response
            return document
        if hop == MAX_HOPS:
            document.response, document.redirect_limit = response, True
            return document
        document.hops.append(current)
        current = target
    return document  # unreachable: the loop returns on every path
