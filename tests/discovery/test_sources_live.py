"""Smoke test of the real CT providers. Excluded from normal runs: ``pytest -m live``.

Providers may be down, rate limited or slow (crt.sh often is); any *typed* outcome is
acceptable. What must hold is that a successful answer parses into plausible names, i.e. that
our parsers still match the providers' real response formats.
"""

from __future__ import annotations

import httpx
import pytest

from app.service.discovery import canonicalise_domain, run_discovery
from app.service.discovery.sources import CertSpotterSource, CrtShSource, CtlogsSource
from app.service.discovery.sources.base import DiscoverySource

pytestmark = pytest.mark.live

DOMAIN = "web-check.xyz"  # small: a handful of certificates


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    with httpx.Client(
        timeout=30, headers={"User-Agent": "Gaprism-live-test/0.1"}, follow_redirects=False
    ) as http:
        yield http


@pytest.mark.parametrize("make", [CtlogsSource, CertSpotterSource, CrtShSource])
def test_each_source_answers_with_a_typed_outcome(client: httpx.Client, make: type) -> None:
    source: DiscoverySource = make(client)
    outcome = source.fetch(DOMAIN)

    assert outcome.status in ("ok", "unavailable", "error")
    if outcome.status != "ok":
        assert outcome.reason_code, "a failure must carry a reason"
        pytest.skip(f"{source.key}: {outcome.status} ({outcome.reason_code})")
    names = {name.name for name in outcome.names}
    assert names, "the domain has certificates, so a successful answer must name something"
    assert any(name == DOMAIN or name.endswith("." + DOMAIN) for name in names)
    assert all(name == name.lower() and " " not in name for name in names)


def test_discovery_over_all_sources_finds_the_apex_or_reports_why_not(client: httpx.Client) -> None:
    scope = canonicalise_domain(DOMAIN)
    sources = [CtlogsSource(client), CertSpotterSource(client), CrtShSource(client)]
    result = run_discovery(scope, sources, mode="union", max_hosts=200)

    if result.sources_ok == 0:
        pytest.skip("every CT source is unavailable right now: " + str(result.to_data()["sources"]))
    assert DOMAIN in {host.hostname for host in result.hosts}
    assert all(host.hostname.endswith(DOMAIN) for host in result.hosts)
