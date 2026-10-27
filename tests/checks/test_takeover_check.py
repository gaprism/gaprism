"""The takeover check over mocked services: no network, no database.

The pages are the real "unclaimed" pages of the services (recorded 2026-10-07, shortened), so the
signatures are tested against what the services really send.
"""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome, waits_for
from app.checks.fetch import MAX_DOCUMENT_BYTES
from app.checks.takeover import BUDGET_SECONDS, MAX_CANDIDATES, TakeoverCheck
from app.checks.takeover_services import CHECKED_ON, SOURCE
from runner.egress import EgressHTTPClient

HOST = "shop.vendor.example"
IP = "93.184.216.34"
ELSEWHERE = "93.184.216.99"
AGENT = "Gaprism-test"

GITHUB_UNCLAIMED = (
    "<!DOCTYPE html><html><head><title>Site not found &middot; GitHub Pages</title></head>"
    "<body><div class='container'><h1>404</h1><p><strong>There isn't a GitHub Pages site "
    "here.</strong></p><p>If you're trying to publish one, read the full documentation</p>"
    "</div></body></html>"
)
HEROKU_UNCLAIMED = (
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>No such app</title></head>'
    '<body><iframe src="//www.herokucdn.com/error-pages/no-such-app.html"></iframe></body></html>'
)
NETLIFY_UNCLAIMED_TEXT = "Not Found - Request ID: 01M4AHSAVJ05DK6G5KH3M7TTQH"
NETLIFY_UNCLAIMED_HTML = (
    "<!doctype html><html><title>Site not found</title><p>Looks like you followed a broken link "
    "or entered a URL that doesn\N{RIGHT SINGLE QUOTATION MARK}t exist on Netlify.</p>"
)
S3_UNCLAIMED = (
    '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The '
    "specified bucket does not exist</Message></Error>"
)
ORDINARY_SITE = (
    "<html><head><title>Vendor shop</title></head><body>Welcome to our shop</body></html>"
)


def html(status: int, body: str, kind: str = "text/html; charset=utf-8") -> httpx.Response:
    return httpx.Response(status, content=body.encode(), headers={"content-type": kind})


def redirect(location: str, status: int = 301) -> httpx.Response:
    return httpx.Response(status, headers={"location": location}, content=b"moved")


class Web:
    """A mock web keyed by (scheme, Host); an unlisted request gets an ordinary page."""

    def __init__(self, pages: dict[tuple[str, str], Any] | None = None) -> None:
        self.pages = pages or {}
        self.requests: list[tuple[str, str, str]] = []
        self.headers: list[httpx.Headers] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        self.requests.append((request.url.scheme, host, request.url.path))
        self.headers.append(request.headers)
        page = self.pages.get((request.url.scheme, host))
        if isinstance(page, Exception):
            raise page
        return page if page is not None else html(200, ORDINARY_SITE)


def dns(
    *targets: str,
    addresses: tuple[str, ...] = (IP,),
    dangling: bool = False,
    canonical: str | None = None,
) -> CheckOutcome:
    """What the DNS check stores for ``HOST``: a CNAME chain through ``targets``."""
    steps: list[dict[str, Any]] = []
    name = HOST
    for target in targets:
        steps.append({"name": name, "target": target, "ttl": 300})
        name = target
    data: dict[str, Any] = {
        "cname": steps,
        "canonical_name": canonical or name,
        "dangling_cname": dangling,
        "addresses": list(addresses),
        "blocked": [],
        "errors": {},
    }
    return CheckOutcome("ok", data=data, source="dns:1.1.1.1")


def run(
    web: Callable[[httpx.Request], httpx.Response],
    previous: CheckOutcome,
    *,
    monotonic: Callable[[], float] | None = None,
) -> CheckOutcome:
    def factory(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            custom_transport=httpx.MockTransport(web),
            resolver_fn=resolver_fn,
            max_response_bytes=MAX_DOCUMENT_BYTES,
            truncate_body=True,
        )

    kwargs: dict[str, Any] = {"monotonic": monotonic} if monotonic else {}
    check = TakeoverCheck(
        client_factory=factory, name_resolver=lambda config, name: [ELSEWHERE], **kwargs
    )
    ctx = CheckContext(
        domain="vendor.example",
        hostname=HOST,
        config={"USER_AGENT": AGENT},
        http=httpx.Client(),
        previous={"dns": previous},
    )
    return check.run(ctx)


def only(outcome: CheckOutcome) -> dict[str, Any]:
    (candidate,) = outcome.data["candidates"]
    assert isinstance(candidate, dict)
    return candidate


def tls_failure() -> httpx.ConnectError:
    error = httpx.ConnectError("the certificate is for another name")
    error.__cause__ = ssl.SSLCertVerificationError("hostname mismatch")
    return error


def refused() -> httpx.ConnectError:
    error = httpx.ConnectError("nothing listens here")
    error.__cause__ = ConnectionRefusedError()
    return error


# ------------------------------------------------------------------------------ the contract


def test_it_is_a_host_check_that_needs_the_dns_answer() -> None:
    check = TakeoverCheck()
    assert (check.key, check.scope, check.needs) == ("takeover", "host", ("dns",))
    assert waits_for(check) == ("dns",)


def test_a_host_that_is_not_an_alias_costs_no_request() -> None:
    web = Web()
    outcome = run(web, dns())
    assert (outcome.status, outcome.source) == ("ok", SOURCE)
    assert outcome.data["aliases"] == [] and outcome.data["candidates"] == []
    assert outcome.data["fingerprints"] == CHECKED_ON and web.requests == []


def test_an_alias_for_a_service_that_is_not_listed_costs_no_request() -> None:
    web = Web()
    outcome = run(web, dns("lb-7.cdn-provider.example"))
    assert outcome.status == "ok" and outcome.data["candidates"] == []
    assert outcome.data["aliases"] == [
        {"name": HOST, "target": "lb-7.cdn-provider.example"}
    ]  # the chain is still reported
    assert web.requests == []


# ------------------------------------------------------------------------------ pages


def test_a_name_the_service_says_nobody_has_claimed_is_unclaimed() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    outcome = run(web, dns("vendor.github.io"))
    assert outcome.status == "ok"
    candidate = only(outcome)
    assert candidate["service"] == "github_pages" and candidate["name"] == "GitHub Pages"
    assert candidate["verdict"] == "unclaimed" and candidate["how"] == "page"
    assert candidate["claim"] == "conditional" and candidate["target"] == "vendor.github.io"
    assert candidate["status"] == 404 and candidate["url"] == f"http://{HOST}/"
    assert candidate["signature"] == "There isn't a GitHub Pages site here."


def test_the_page_itself_is_never_stored() -> None:
    outcome = run(Web({("http", HOST): html(404, GITHUB_UNCLAIMED)}), dns("vendor.github.io"))
    stored = json.dumps(outcome.data)
    assert "Site not found" not in stored and "container" not in stored


def test_the_request_is_the_one_any_visitor_sends() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    run(web, dns("vendor.github.io"))
    assert web.requests == [("http", HOST, "/")]  # the host's own name, over plain HTTP, once
    headers = web.headers[0]
    assert headers["user-agent"] == AGENT and "text/html" in headers["accept"]
    assert "authorization" not in headers and "cookie" not in headers


def test_a_service_that_serves_a_real_site_is_in_use() -> None:
    outcome = run(Web({("http", HOST): html(200, ORDINARY_SITE)}), dns("vendor.github.io"))
    candidate = only(outcome)
    assert outcome.status == "ok" and candidate["verdict"] == "in_use"
    assert candidate["status"] == 200 and candidate["signature"] is None


def test_the_unclaimed_text_with_the_wrong_status_is_not_an_unclaimed_name() -> None:
    """A blog post that quotes the service's error page is not the error page."""
    outcome = run(Web({("http", HOST): html(200, GITHUB_UNCLAIMED)}), dns("vendor.github.io"))
    assert only(outcome)["verdict"] == "in_use"


def test_a_404_of_a_site_that_exists_is_not_unclaimed() -> None:
    page = html(404, "<html><title>Not found</title><h1>This page does not exist</h1></html>")
    outcome = run(Web({("http", HOST): page}), dns("vendor.github.io"))
    assert only(outcome)["verdict"] == "in_use" and only(outcome)["status"] == 404


def test_the_signature_is_found_whatever_the_case_entities_or_spacing() -> None:
    body = "<p>THERE ISN&#39;T  a GitHub\n Pages site here.</p>"
    outcome = run(Web({("http", HOST): html(404, body)}), dns("vendor.github.io"))
    assert only(outcome)["verdict"] == "unclaimed"


@pytest.mark.parametrize(
    ("target", "body", "kind", "key"),
    [
        ("shop-1.herokuapp.com", HEROKU_UNCLAIMED, "text/html", "heroku"),
        ("abc-123.herokudns.com", HEROKU_UNCLAIMED, "text/html", "heroku"),
        ("shop.vendor.example.s3.amazonaws.com", S3_UNCLAIMED, "application/xml", "aws_s3"),
        ("x.s3-website-us-east-1.amazonaws.com", S3_UNCLAIMED, "text/html", "aws_s3"),
        ("vendor.netlify.app", NETLIFY_UNCLAIMED_TEXT, "text/plain", "netlify"),
        ("vendor.netlify.app", NETLIFY_UNCLAIMED_HTML, "text/html", "netlify"),  # a browser's page
        ("cname.vercel-dns.com", "DEPLOYMENT_NOT_FOUND\nlhr1::abc", "text/plain", "vercel"),
        ("vendor.surge.sh", "<title>project not found</title>", "text/html", "surge"),
        (
            "live-vendor.pantheonsite.io",
            "<title>404 - Unknown site</title>",
            "text/html",
            "pantheon",
        ),
        (
            "forwarding.tilda.ws",
            "Please go to the site settings and put the domain name in the Domain tab.",
            "text/html",
            "tilda",
        ),
    ],
)
def test_the_unclaimed_page_of_every_listed_service_is_recognised(
    target: str, body: str, kind: str, key: str
) -> None:
    outcome = run(Web({("http", HOST): html(404, body, kind)}), dns(target))
    assert only(outcome)["service"] == key and only(outcome)["verdict"] == "unclaimed"


def test_the_service_decides_which_signature_counts() -> None:
    """GitHub's text on a host that is an alias for Heroku proves nothing."""
    outcome = run(Web({("http", HOST): html(404, GITHUB_UNCLAIMED)}), dns("shop.herokuapp.com"))
    assert only(outcome)["service"] == "heroku" and only(outcome)["verdict"] == "in_use"


def test_an_alias_chain_through_the_vendors_own_names_still_reaches_the_service() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    outcome = run(web, dns("www.vendor.example", "vendor.github.io"))
    assert only(outcome)["target"] == "vendor.github.io" and only(outcome)["verdict"] == "unclaimed"
    assert [alias["target"] for alias in outcome.data["aliases"]] == [
        "www.vendor.example",
        "vendor.github.io",
    ]


def test_two_services_in_one_chain_share_one_request() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    outcome = run(web, dns("vendor.github.io", "vendor.netlify.app"))
    verdicts = {c["service"]: c["verdict"] for c in outcome.data["candidates"]}
    assert verdicts == {"github_pages": "unclaimed", "netlify": "in_use"}
    assert len(web.requests) == 1


def test_a_chain_through_more_services_than_the_cap_is_cut_and_says_so() -> None:
    targets = ("a.github.io", "b.netlify.app", "c.surge.sh", "d.herokuapp.com")
    outcome = run(Web(), dns(*targets))
    assert len(outcome.data["candidates"]) == MAX_CANDIDATES == 3
    assert outcome.data["candidates_cut"] == 1


# ------------------------------------------------------------------------------ getting the page


def test_https_is_asked_only_when_plain_http_got_no_answer() -> None:
    web = Web({("http", HOST): refused(), ("https", HOST): html(404, GITHUB_UNCLAIMED)})
    outcome = run(web, dns("vendor.github.io"))
    assert [(scheme, path) for scheme, _, path in web.requests] == [("http", "/"), ("https", "/")]
    candidate = only(outcome)
    assert candidate["verdict"] == "unclaimed" and candidate["url"] == f"https://{HOST}/"


def test_a_redirect_to_a_page_that_says_unclaimed_is_followed_through_the_gate() -> None:
    web = Web(
        {
            ("http", HOST): redirect(f"https://{HOST}/welcome"),
            ("https", HOST): html(404, GITHUB_UNCLAIMED),
        }
    )
    outcome = run(web, dns("vendor.github.io"))
    assert only(outcome)["verdict"] == "unclaimed"
    assert [(s, p) for s, _, p in web.requests] == [("http", "/"), ("https", "/welcome")]


def test_a_redirect_to_https_that_cannot_be_verified_is_not_tested_never_in_use() -> None:
    """The egress gate never turns certificate verification off, so the page cannot be read."""
    web = Web({("http", HOST): redirect(f"https://{HOST}/"), ("https", HOST): tls_failure()})
    outcome = run(web, dns("vendor.github.io"))
    assert (outcome.status, outcome.reason_code) == ("error", "tls_verification_failed")
    candidate = only(outcome)
    assert candidate["verdict"] == "not_tested" and candidate["error"] == "tls_verification_failed"
    assert len(web.requests) == 2  # no third request: HTTPS was the redirect's own target


def test_nothing_answering_at_all_is_an_error_with_the_reason() -> None:
    timeout = httpx.ReadTimeout("slow")
    web = Web({("http", HOST): timeout, ("https", HOST): timeout})
    outcome = run(web, dns("vendor.github.io"))
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")
    assert only(outcome)["verdict"] == "not_tested"
    assert outcome.data["aliases"]  # what DNS said is still there


def test_an_alias_with_no_public_address_to_ask_is_skipped() -> None:
    web = Web()
    outcome = run(web, dns("vendor.github.io", addresses=()))
    assert (outcome.status, outcome.reason_code) == ("skipped", "no_public_address")
    assert only(outcome)["verdict"] == "not_tested" and web.requests == []


def test_what_could_not_be_tested_does_not_hide_what_could() -> None:
    outcome = run(
        Web(),
        dns(
            "vendor.azurewebsites.net",
            "x.github.io",
            addresses=(),
            dangling=True,
            canonical="vendor.azurewebsites.net",
        ),
    )
    by_service = {c["service"]: c for c in outcome.data["candidates"]}
    assert by_service["azure"]["verdict"] == "claimable"  # DNS alone decides this one
    assert by_service["github_pages"]["verdict"] == "not_tested"
    assert outcome.status == "ok"


def test_a_check_that_ran_out_of_time_says_so() -> None:
    clock = iter([0.0, BUDGET_SECONDS + 1])  # start; then the first page candidate is too late
    outcome = run(Web(), dns("vendor.github.io"), monotonic=lambda: next(clock))
    assert (outcome.status, outcome.reason_code) == ("error", "budget_exceeded")
    assert only(outcome)["verdict"] == "not_tested"


# ----------------------------------------------------------------------- names that do not exist


def test_an_alias_for_a_name_nobody_registered_is_claimable_without_any_request() -> None:
    web = Web()
    outcome = run(web, dns("vendor.azurewebsites.net", addresses=(), dangling=True))
    candidate = only(outcome)
    assert outcome.status == "ok" and candidate["verdict"] == "claimable"
    assert candidate["service"] == "azure" and candidate["claim"] == "open"
    assert candidate["how"] == "dns" and candidate["status"] is None and web.requests == []


def test_an_alias_for_a_name_that_exists_is_in_use() -> None:
    web = Web()
    outcome = run(web, dns("vendor.azurewebsites.net", addresses=("20.50.2.3",)))
    assert only(outcome)["verdict"] == "in_use" and web.requests == []


def test_a_dangling_chain_that_ends_elsewhere_does_not_blame_the_service_before_it() -> None:
    """The alias for the service resolves; it is the vendor's own name after it that is missing."""
    outcome = run(
        Web(), dns("vendor.azurewebsites.net", "old.vendor.example", addresses=(), dangling=True)
    )
    assert only(outcome)["verdict"] == "in_use"


def test_a_dangling_alias_for_a_service_that_is_not_listed_is_left_to_the_dns_rule() -> None:
    outcome = run(Web(), dns("gone.somewhere.example", addresses=(), dangling=True))
    assert outcome.status == "ok" and outcome.data["candidates"] == []
