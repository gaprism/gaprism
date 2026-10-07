"""TECH_OUTDATED_VERSION and SCRIPT_FROM_COMPROMISED_HOST, over what the real HTTP and technology
checks make of a scripted first page."""

from __future__ import annotations

import datetime
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.tech import TechCheck
from app.rules import RULES
from app.service.findings import render_value
from tests.checks.test_http_check import HOST, page
from tests.rules.helpers import GOOD_HEADERS, fire, host, one, web

TODAY = datetime.date(2026, 10, 7)
DNS = CheckOutcome(
    "ok", data={"cname": [], "canonical_name": HOST, "addresses": ["93.184.216.34"]}, source="dns"
)


def judged(
    body: str = "<html></html>",
    headers: list[tuple[str, str]] | None = None,
    *,
    http: CheckOutcome | None = None,
) -> Any:
    """The host as the stored results of a scan would show it: the first page (or the ``http``
    result given instead), then what the technology check makes of it."""
    http = http or web(https=page(200, [*GOOD_HEADERS, *(headers or [])], body=body))
    context = CheckContext(
        domain="example.com",
        hostname=HOST,
        config={},
        http=httpx.Client(),
        previous={"dns": DNS, "http": http},
    )
    tech = TechCheck(clock=lambda: TODAY).run(context)
    return host(HOST, dns=DNS, http=http, tech=tech)


def script(url: str) -> str:
    return f'<html><head><script src="{url}"></script></head></html>'


# ------------------------------------------------------------------------ TECH_OUTDATED_VERSION


def test_a_version_that_only_a_header_shows_is_low_with_low_confidence() -> None:
    subject = judged(headers=[("X-Powered-By", "PHP/7.4.33")])
    draft = one("TECH_OUTDATED_VERSION", subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "low",
        "low",
        "hostname_supported",
    )
    assert draft.subject == f"host:{HOST}"
    assert draft.params["outdated"] == ["PHP 7.4.33"]
    assert draft.params["details"] == ["PHP 7.4 ended on 2022-11-28"]
    assert draft.params["version_from"] == ["header"]
    assert draft.evidence == (subject.results["tech"].id, subject.results["http"].id)
    assert draft.host_id == subject.id


def test_a_version_the_page_itself_shows_is_medium_confidence() -> None:
    draft = one("TECH_OUTDATED_VERSION", judged(script("/assets/jquery-1.12.4.min.js")))
    assert (draft.severity, draft.confidence) == ("low", "medium")
    assert draft.params["outdated"] == ["jQuery 1.12.4"]
    assert draft.params["version_from"] == ["path"]
    assert "3.5" in draft.params["details"][0]


def test_one_finding_names_every_old_product_and_the_page_sets_the_confidence() -> None:
    subject = judged(script("/js/jquery-1.12.4.min.js"), headers=[("X-Powered-By", "PHP/7.4.33")])
    draft = one("TECH_OUTDATED_VERSION", subject)
    assert set(draft.params["outdated"]) == {"PHP 7.4.33", "jQuery 1.12.4"}
    assert draft.params["version_from"] == ["header", "path"]
    assert draft.confidence == "medium"  # one of the two versions is shown by the page itself


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Powered-By", "PHP/8.3.1"), ("Server", "nginx/1.25.3")],
        [("Server", "nginx/1.10.3")],  # old, but the ruleset has no dates for nginx: not judged
        [],
    ],
)
def test_current_versions_and_products_without_dates_give_no_finding(
    headers: list[tuple[str, str]],
) -> None:
    assert fire("TECH_OUTDATED_VERSION", judged(headers=headers)) == []


def test_a_current_library_gives_no_finding() -> None:
    assert fire("TECH_OUTDATED_VERSION", judged(script("/js/jquery-3.7.1.min.js"))) == []


@pytest.mark.parametrize("outcome", [None, CheckOutcome("error", reason_code="timeout")])
def test_without_a_technology_result_the_rule_stays_silent(outcome: CheckOutcome | None) -> None:
    results = {"http": web()} | ({"tech": outcome} if outcome else {})
    assert fire("TECH_OUTDATED_VERSION", host(HOST, **results)) == []
    assert fire("SCRIPT_FROM_COMPROMISED_HOST", host(HOST, **results)) == []


def test_the_rule_is_always_low() -> None:
    assert RULES["TECH_OUTDATED_VERSION"].severities == ("low",)


# ------------------------------------------------------------------ SCRIPT_FROM_COMPROMISED_HOST


def test_a_script_from_a_host_that_served_malware_is_high_with_medium_confidence() -> None:
    subject = judged(script("https://cdn.polyfill.io/v3/polyfill.min.js?features=fetch"))
    draft = one("SCRIPT_FROM_COMPROMISED_HOST", subject)
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "high",
        "medium",
        "hostname_supported",
    )
    assert draft.params["flagged"] == ["cdn.polyfill.io"]
    assert draft.params["loaded_as"] == ["script"]
    assert draft.evidence == (subject.results["tech"].id, subject.results["http"].id)


def test_a_frame_counts_like_a_script() -> None:
    body = '<html><iframe src="https://cdn.bootcss.com/x.html"></iframe></html>'
    draft = one("SCRIPT_FROM_COMPROMISED_HOST", judged(body))
    assert (draft.severity, draft.confidence) == ("high", "medium")
    assert draft.params["loaded_as"] == ["iframe"]


@pytest.mark.parametrize(
    "body, kind",
    [
        ('<html><link rel="stylesheet" href="https://cdn.bootcss.com/x.css"></html>', "link"),
        ('<html><img src="https://static.staticfile.org/logo.png"></html>', "img"),
        (
            "<html><script>var u = 'https://cdn.bootcss.com/jquery/1.12.4/jquery.min.js';"
            "</script></html>",
            "inline",
        ),
    ],
)
def test_a_style_sheet_an_image_or_a_mention_is_medium_with_low_confidence(
    body: str, kind: str
) -> None:
    draft = one("SCRIPT_FROM_COMPROMISED_HOST", judged(body))
    assert (draft.severity, draft.confidence) == ("medium", "low")
    assert draft.params["loaded_as"] == [kind]


def test_when_code_and_a_style_sheet_come_from_such_hosts_the_code_is_named() -> None:
    body = (
        '<html><link rel="stylesheet" href="https://cdn.bootcss.com/x.css">'
        '<script src="https://cdn.polyfill.io/v3/polyfill.js"></script></html>'
    )
    draft = one("SCRIPT_FROM_COMPROMISED_HOST", judged(body))
    assert draft.severity == "high"
    assert draft.params["flagged"] == ["cdn.polyfill.io"]
    assert draft.params["loaded_as"] == ["link", "script"]


@pytest.mark.parametrize(
    "url",
    [
        "https://polyfill.io.example.org/x.js",  # a longer name, not a host of that domain
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        "/js/polyfill.js",  # the page's own copy
    ],
)
def test_other_hosts_and_a_copy_of_the_site_are_no_finding(url: str) -> None:
    assert fire("SCRIPT_FROM_COMPROMISED_HOST", judged(script(url))) == []


def test_the_rule_is_medium_or_high() -> None:
    assert RULES["SCRIPT_FROM_COMPROMISED_HOST"].severities == ("medium", "high")


# ------------------------------------------------------------------------------ in words


def test_the_codes_of_the_facts_read_as_words() -> None:
    assert render_value("version_from", ["header", "path"]) == "a server header, a file name"
    assert render_value("loaded_as", ["script", "inline"]) == "script, named in an inline script"
