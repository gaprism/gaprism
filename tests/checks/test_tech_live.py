"""The technology check over real sites. Needs the network: run with ``pytest -m live``.

The real DNS and HTTP checks run against a few well-known hosts (the requests every visitor sends:
DNS questions and one or two page requests) and the technology check reads what they stored. These
notice when a site, or the way a vendor shows itself, changes so that an entry of the ruleset no
longer matches; they say nothing about what is *not* listed, which is never a statement of absence.
"""

from __future__ import annotations

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import DnsCheck
from app.checks.http import HttpCheck
from app.checks.tech import TechCheck

pytestmark = pytest.mark.live

CONFIG = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "USER_AGENT": "WebDueDiligence-live-test",
    "EGRESS_CONNECT_TIMEOUT_SEC": 8,
    "EGRESS_READ_TIMEOUT_SEC": 15,
}


def technologies_of(host: str) -> CheckOutcome:
    previous: dict[str, CheckOutcome] = {}

    def context() -> CheckContext:
        return CheckContext(
            domain=host, hostname=host, config=CONFIG, http=httpx.Client(), previous=dict(previous)
        )

    previous["dns"] = DnsCheck().run(context())
    assert previous["dns"].status == "ok", previous["dns"].reason_code
    previous["http"] = HttpCheck().run(context())
    assert previous["http"].status == "ok", previous["http"].reason_code
    return TechCheck().run(context())


def keys(outcome: CheckOutcome) -> set[str]:
    return {item["key"] for item in outcome.data["technologies"]}


def test_cloudflare_is_recognised_in_front_of_its_own_site() -> None:
    outcome = technologies_of("www.cloudflare.com")
    assert outcome.status == "ok" and "Cloudflare" in outcome.data["edge"]
    cloudflare = next(t for t in outcome.data["technologies"] if t["key"] == "cloudflare")
    assert cloudflare["confidence"] == "high" and {e["kind"] for e in cloudflare["evidence"]}


def test_wordpress_org_is_recognised_with_a_version_and_what_comes_with_it() -> None:
    outcome = technologies_of("wordpress.org")
    found = {t["key"]: t for t in outcome.data["technologies"]}
    assert {"wordpress", "php", "nginx"} <= set(found)
    assert found["wordpress"]["version"] and found["wordpress"]["confidence"] == "high"
    assert found["php"]["implied_by"] == "WordPress"  # implied, not seen: never claimed more
    assert outcome.data["page"]["read"] is True and outcome.data["outdated"] == []


def test_a_site_behind_several_layers_names_each_of_them() -> None:
    outcome = technologies_of("getbootstrap.com")  # Cloudflare in front of GitHub Pages and Fastly
    assert {"cloudflare", "fastly", "github", "bootstrap"} <= keys(outcome)
    assert {"Cloudflare", "Fastly"} <= set(outcome.data["edge"])


def test_a_host_that_redirects_to_another_is_not_given_that_hosts_technologies() -> None:
    outcome = technologies_of("google.com")  # answers with a redirect to www.google.com
    assert outcome.data["page"]["redirected_to"] == "www.google.com"
    assert outcome.data["page"]["read"] is False
    assert keys(outcome) == set()  # nothing of www.google.com's response is read as this host's
