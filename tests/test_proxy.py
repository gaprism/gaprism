"""Behind a reverse proxy: whose address the app believes, and why the sign-in limit needs it."""

from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask, request
from flask.testing import FlaskClient

from app import create_app
from app.config import MAX_TRUSTED_PROXIES, ConfigurationError, TestingConfig, validate_config
from app.extensions import db
from app.web import log as web_log
from tests.helpers import make_app

PROXY = "172.18.0.5"  # the reverse proxy: the address the app's connection comes from
CLIENT = "203.0.113.9"


def probe_app(hops: int) -> Flask:
    """An application (no database needed) with a route that says what the app believes."""
    config = type("Proxied", (TestingConfig,), {"TRUSTED_PROXY_COUNT": hops})
    app = create_app(config)
    app.add_url_rule("/_probe", "probe", lambda: f"{request.remote_addr} {request.scheme}")
    return app


def ask(app: Flask, **headers: str) -> tuple[str, str]:
    """(address, scheme) as the app sees a request that comes from the proxy's connection."""
    response = app.test_client().get(
        "/_probe", headers=headers, environ_base={"REMOTE_ADDR": PROXY}
    )
    address, scheme = response.get_data(as_text=True).split()
    return address, scheme


def forwarded(value: str) -> dict[str, str]:
    return {"X-Forwarded-For": value}


# ------------------------------------------------------------------------------ what is believed


def test_without_a_trusted_proxy_the_forwarding_headers_are_ignored() -> None:
    app = probe_app(0)
    headers = {"X-Forwarded-For": CLIENT, "X-Forwarded-Proto": "https"}
    assert ask(app, **headers) == (PROXY, "http")  # a client could say anything


def test_one_trusted_proxy_tells_the_address_and_the_scheme() -> None:
    app = probe_app(1)
    assert ask(app, **{"X-Forwarded-For": CLIENT, "X-Forwarded-Proto": "https"}) == (
        CLIENT,
        "https",
    )
    assert ask(app) == (PROXY, "http")  # no header: the connection is all there is


def test_a_client_cannot_choose_its_address_by_sending_the_header_itself() -> None:
    """The proxy appends the address it saw to whatever the client sent: only that entry counts."""
    app = probe_app(1)
    assert ask(app, **forwarded(f"198.51.100.1, {CLIENT}")) == (CLIENT, "http")
    assert ask(app, **forwarded(f"198.51.100.1, 192.0.2.7, {CLIENT}")) == (CLIENT, "http")


def test_more_trusted_proxies_look_further_to_the_left() -> None:
    app = probe_app(2)  # a load balancer in front of the reverse proxy
    assert ask(app, **forwarded(f"{CLIENT}, 10.0.0.8")) == (CLIENT, "http")
    assert ask(app, **forwarded(f"198.51.100.1, {CLIENT}, 10.0.0.8")) == (CLIENT, "http")


def test_a_header_with_fewer_entries_than_trusted_proxies_is_not_believed() -> None:
    app = probe_app(2)
    assert ask(app, **forwarded(CLIENT)) == (PROXY, "http")  # a second proxy that is not there


def test_the_host_header_is_never_taken_from_a_proxy() -> None:
    app = probe_app(1)
    app.add_url_rule("/_host", "host", lambda: request.host)
    response = app.test_client().get(
        "/_host",
        headers={
            "Host": "dd.example.org",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-For": CLIENT,
        },
        environ_base={"REMOTE_ADDR": PROXY},
    )
    assert response.get_data(as_text=True) == "dd.example.org"


# ------------------------------------------------------------------------------ a proxy nobody told


def test_a_forwarding_header_with_no_trusted_proxy_is_reported_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = probe_app(0)
    client = app.test_client()
    with caplog.at_level(logging.WARNING, logger=web_log.name):
        for _ in range(3):
            client.get("/_probe", headers=forwarded(CLIENT))
        client.get("/_probe")
    messages = [r.getMessage() for r in caplog.records if r.name == web_log.name]
    assert len(messages) == 1 and "TRUSTED_PROXY_COUNT=1" in messages[0]
    assert CLIENT not in messages[0]  # what clients send does not go to the log


def test_nothing_is_reported_when_no_forwarding_header_arrives(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = probe_app(0)
    with caplog.at_level(logging.WARNING, logger=web_log.name):
        app.test_client().get("/_probe")
    assert not [r for r in caplog.records if r.name == web_log.name]


# ------------------------------------------------------------------------------ the setting


@pytest.mark.parametrize("bad", [-1, MAX_TRUSTED_PROXIES + 1, True, "1", 1.5])
def test_the_number_of_proxies_must_be_a_small_non_negative_integer(bad: object) -> None:
    config = type("BadProxies", (TestingConfig,), {"TRUSTED_PROXY_COUNT": bad})
    with pytest.raises(ConfigurationError, match="TRUSTED_PROXY_COUNT must be an integer"):
        validate_config(config)


def test_the_number_of_proxies_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert create_app("development").config["TRUSTED_PROXY_COUNT"] == 0
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    assert create_app("development").config["TRUSTED_PROXY_COUNT"] == 1
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "")  # an empty line in .env: not set
    assert create_app("development").config["TRUSTED_PROXY_COUNT"] == 0
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "many")
    with pytest.raises(ConfigurationError, match="TRUSTED_PROXY_COUNT must be an integer"):
        create_app("development")


# ------------------------------------------------------------------------------ the sign-in limit


@pytest.fixture
def clean_buckets(app: Flask) -> Generator[None, None, None]:
    """The limiter commits its counters; leave none behind for the tests that follow."""
    yield
    with app.app_context():
        db.session.execute(sa.text("DELETE FROM auth_rate_limit_bucket"))
        db.session.commit()


def fail_to_sign_in(client: FlaskClient, who: str, address: str, times: int) -> list[int]:
    """Wrong passwords from ``address`` as the proxy reports it; the answers' status codes."""
    return [
        client.post(
            "/auth/login",
            data={"email": who, "password": "wrong"},
            headers=forwarded(address),
            environ_base={"REMOTE_ADDR": PROXY},
        ).status_code
        for _ in range(times)
    ]


def sign_in_codes(database_url: str, schema_name: str, hops: int, **extra: Any) -> tuple[int, int]:
    """Status of the next attempt of client B after client A failed five times."""
    app = make_app(database_url, schema_name, TRUSTED_PROXY_COUNT=hops, **extra)
    with app.app_context():
        client = app.test_client()
        fail_to_sign_in(client, "a@example.org", "203.0.113.1", 5)
        a_next = fail_to_sign_in(client, "a@example.org", "203.0.113.1", 1)[0]
        b_next = fail_to_sign_in(client, "b@example.org", "203.0.113.2", 1)[0]
        return a_next, b_next


@pytest.mark.usefixtures("clean_buckets")
def test_behind_a_trusted_proxy_one_clients_failures_do_not_block_the_others(
    database_url: str, schema_name: str
) -> None:
    assert sign_in_codes(database_url, schema_name, hops=1) == (429, 200)


@pytest.mark.usefixtures("clean_buckets")
def test_without_it_every_client_behind_the_proxy_shares_one_address_and_one_budget(
    database_url: str, schema_name: str
) -> None:
    """What TRUSTED_PROXY_COUNT is for: the proxy's address is the same for everybody."""
    assert sign_in_codes(database_url, schema_name, hops=0) == (429, 429)
