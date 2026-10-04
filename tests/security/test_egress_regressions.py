"""Verify connection identity and collection bounds, not just a preliminary DNS check."""

import httpx
import pytest

from runner.dns import SSRFBlockedError
from runner.egress import EgressHTTPClient


def test_http_destination_is_pinned_and_tls_identity_preserved() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "target.example.com"
        assert request.extensions["sni_hostname"] == "target.example.com"
        return httpx.Response(200, text="synthetic")

    client = EgressHTTPClient(
        resolver_fn=lambda host: ["93.184.216.34"], custom_transport=httpx.MockTransport(handler)
    )
    assert client.get("https://target.example.com/").connected_ip == "93.184.216.34"
    assert len(calls) == 1


def test_bounded_response() -> None:
    client = EgressHTTPClient(
        max_response_bytes=4,
        resolver_fn=lambda host: ["93.184.216.34"],
        custom_transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"12345")),
    )
    with pytest.raises(SSRFBlockedError, match="byte limit"):
        client.get("https://target.example.com/")


@pytest.mark.parametrize("url", ["https://user:password@example.com/", "https://example.com:8443/"])
def test_credentials_and_nonstandard_ports_rejected_before_resolution(url: str) -> None:
    def forbidden_resolution(host: str) -> list[str]:
        raise AssertionError("must reject before DNS")

    with pytest.raises(SSRFBlockedError):
        EgressHTTPClient(resolver_fn=forbidden_resolution).get(url)
