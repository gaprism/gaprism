"""ctlogs.dev documented hosts contract, without contacting the provider."""

from typing import Any

import httpx
import pytest

from app.service.discovery.ct import CTDiscoveryAdapter, CTDiscoveryError


def test_hosts_endpoint_bearer_auth_and_cursor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/hosts/example.com"
        assert request.url.params["after"] == "opaque-cursor"
        assert request.headers["Authorization"] == "Bearer fixture-key"
        assert "fixture-key" not in str(request.url)
        return httpx.Response(
            200,
            json={
                "hosts": [
                    {"host": "api.example.com", "certs": 3, "first_seen": "2026-01-01T00:00:00Z"}
                ],
                "has_next": False,
                "next_cursor": "",
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = CTDiscoveryAdapter(http_client=client, api_key="fixture-key").fetch_page(
            "example.com",
            cursor="opaque-cursor",
        )
    assert result.entries[0].entry_count == 3
    assert not result.has_more


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"error": "unexpected"},
        {"hosts": [], "has_next": True, "next_cursor": ""},
        {"hosts": [{"host": "example.com", "certs": "3"}], "has_next": False},
    ],
)
def test_malformed_payload_is_not_an_empty_success(payload: Any) -> None:
    with pytest.raises(CTDiscoveryError):
        CTDiscoveryAdapter.parse_ct_response(payload)


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_provider_errors_never_become_no_match_or_echo_secrets(status: int) -> None:
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, text="fixture-key confidential provider error")
        )
    ) as client:
        with pytest.raises(CTDiscoveryError) as error:
            CTDiscoveryAdapter(http_client=client, api_key="fixture-key").fetch_page("example.com")
    assert str(status) in str(error.value)
    assert "fixture-key" not in str(error.value)
