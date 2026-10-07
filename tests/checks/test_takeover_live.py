"""The takeover check against the real services. Needs the network: run with ``pytest -m live``.

Each service is asked about a name nobody can own: ``wdd-<random>.example.org`` as the host (it
only travels as the ``Host`` header, as a dangling custom domain would) at the addresses of a
random name under the service's own domain, which the service answers with its "nothing here" page.
They notice when a service changes that page, and confirm the signatures in ``takeover_services``.
"""

from __future__ import annotations

import secrets
import socket
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.takeover import TakeoverCheck
from app.checks.takeover_services import SERVICES, Service
from runner.dns import ip_block_reason

pytestmark = pytest.mark.live

# A name under each service's own domain that resolves (the service answers every name there).
EDGES = {
    "github_pages": "github.io",
    "heroku": "herokuapp.com",
    "aws_s3": "s3.amazonaws.com",
    "netlify": "netlify.app",
    "vercel": "vercel.app",
    "surge": "surge.sh",
    "pantheon": "pantheonsite.io",
    "tilda": "tilda.ws",
}
S3_WEBSITE = "s3-website-us-east-1.amazonaws.com"
CONFIG = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "USER_AGENT": "WebDueDiligence-live-test",
}


def public_addresses(name: str) -> list[str]:
    found = {info[4][0] for info in socket.getaddrinfo(name, 80, proto=socket.IPPROTO_TCP)}
    return sorted(ip for ip in found if ip_block_reason(ip) is None)


def alias_of(target: str, host: str, addresses: list[str]) -> CheckOutcome:
    steps = [{"name": host, "target": target, "ttl": 300}]
    data: dict[str, Any] = {
        "cname": steps,
        "canonical_name": target,
        "dangling_cname": False,
        "addresses": addresses,
        "blocked": [],
    }
    return CheckOutcome("ok", data=data)


def run(target: str) -> CheckOutcome:
    host = f"wdd-{secrets.token_hex(5)}.example.org"
    context = CheckContext(
        domain="example.org",
        hostname=host,
        config=CONFIG,
        http=httpx.Client(),
        previous={"dns": alias_of(target, host, public_addresses(target))},
    )
    return TakeoverCheck().run(context)


@pytest.mark.parametrize("key", sorted(EDGES))
def test_a_service_shows_the_page_that_the_ruleset_expects_for_an_unclaimed_name(key: str) -> None:
    outcome = run(f"wdd-{secrets.token_hex(5)}.{EDGES[key]}")
    assert outcome.status == "ok", outcome
    (candidate,) = outcome.data["candidates"]
    assert candidate["service"] == key
    assert candidate["verdict"] == "unclaimed", candidate
    assert candidate["status"] == 404 and candidate["signature"]


def test_the_website_endpoints_of_s3_show_it_too() -> None:
    outcome = run(f"wdd-{secrets.token_hex(5)}.{S3_WEBSITE}")
    (candidate,) = outcome.data["candidates"]
    assert candidate["service"] == "aws_s3" and candidate["verdict"] == "unclaimed", candidate


def test_every_service_that_shows_a_page_is_covered_here() -> None:
    pages = {service.key for service in SERVICES if service.how == "page"}
    assert pages == set(EDGES) | {"aws_s3"}


def dns_services() -> list[Service]:
    return [service for service in SERVICES if service.how == "dns"]


@pytest.mark.parametrize("service", dns_services(), ids=lambda s: s.key)
def test_the_names_of_a_dns_service_do_not_exist_until_somebody_registers_them(
    service: Service,
) -> None:
    for suffix in service.suffixes:
        name = f"wdd-{secrets.token_hex(5)}.{suffix}"
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo(name, 80)
