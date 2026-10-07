"""TAKEOVER_LIKELY and its neighbour DANGLING_CNAME, over what the real takeover check produces."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.checks.base import CheckOutcome
from app.rules import RULES
from tests.checks.test_takeover_check import (
    GITHUB_UNCLAIMED,
    HOST,
    NETLIFY_UNCLAIMED_TEXT,
    ORDINARY_SITE,
    S3_UNCLAIMED,
    Web,
    dns,
    html,
)
from tests.checks.test_takeover_check import run as run_takeover
from tests.rules.helpers import fire, host, one


def facts(previous: CheckOutcome, outcome: CheckOutcome) -> Any:
    return host(HOST, dns=previous, takeover=outcome)


def judged(web: Web, previous: CheckOutcome) -> Any:
    """The host as the stored results of a scan would show it."""
    return facts(previous, run_takeover(web, previous))


def test_an_unclaimed_name_that_anyone_may_claim_is_high_with_high_confidence() -> None:
    previous = dns("shop.vendor.example.s3.amazonaws.com")
    web = Web({("http", HOST): html(404, S3_UNCLAIMED, "application/xml")})
    draft = one("TAKEOVER_LIKELY", judged(web, previous))
    assert (draft.severity, draft.confidence, draft.attribution) == (
        "high",
        "high",
        "hostname_supported",
    )
    assert draft.subject == f"host:{HOST}"
    assert draft.params["service"] == "Amazon S3"
    assert draft.params["target"] == "shop.vendor.example.s3.amazonaws.com"
    assert draft.params["takeover_how"] == "page" and draft.params["takeover_claim"] == "open"
    assert draft.params["status"] == 404
    assert draft.params["signature"] == "The specified bucket does not exist"
    assert draft.params["also"] is None


def test_a_service_that_checks_something_first_makes_it_medium_confidence() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    draft = one("TAKEOVER_LIKELY", judged(web, dns("vendor.github.io")))
    assert (draft.severity, draft.confidence) == ("high", "medium")
    assert (
        draft.params["service"] == "GitHub Pages"
        and draft.params["takeover_claim"] == "conditional"
    )


def test_a_missing_name_that_anyone_may_register_is_high_with_medium_confidence() -> None:
    previous = dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    draft = one("TAKEOVER_LIKELY", judged(Web(), previous))
    assert (draft.severity, draft.confidence) == ("high", "medium")  # the name was not tried
    assert draft.params["takeover_how"] == "dns" and draft.params["status"] is None
    assert draft.params["service"] == "Microsoft Azure"


def test_the_evidence_is_the_dns_answer_and_the_takeover_result() -> None:
    previous = dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    subject = judged(Web(), previous)
    draft = one("TAKEOVER_LIKELY", subject)
    assert draft.evidence == (subject.results["dns"].id, subject.results["takeover"].id)
    assert draft.host_id == subject.id


def test_the_strongest_candidate_speaks_and_the_others_are_named() -> None:
    web = Web({("http", HOST): html(404, NETLIFY_UNCLAIMED_TEXT, "text/plain")})
    draft = one("TAKEOVER_LIKELY", judged(web, dns("vendor.github.io", "vendor.netlify.app")))
    # GitHub is in use here (its page was not shown), Netlify's unclaimed page was seen
    assert draft.params["service"] == "Netlify" and draft.params["also"] is None

    both = Web({("http", HOST): html(404, GITHUB_UNCLAIMED + NETLIFY_UNCLAIMED_TEXT)})
    draft = one("TAKEOVER_LIKELY", judged(both, dns("vendor.github.io", "vendor.netlify.app")))
    assert draft.params["service"] == "GitHub Pages"  # both conditional: by name
    assert draft.params["also"] == ["Netlify"]


def test_params_are_plain_json() -> None:
    web = Web({("http", HOST): html(404, GITHUB_UNCLAIMED)})
    draft = one("TAKEOVER_LIKELY", judged(web, dns("vendor.github.io")))
    assert json.loads(json.dumps(draft.params)) == draft.params


@pytest.mark.parametrize(
    "web",
    [
        Web({("http", HOST): html(200, ORDINARY_SITE)}),  # in use
        Web({("http", HOST): html(200, GITHUB_UNCLAIMED)}),  # the text with a different status
    ],
)
def test_an_alias_that_is_in_use_is_no_finding(web: Web) -> None:
    assert fire("TAKEOVER_LIKELY", judged(web, dns("vendor.github.io"))) == []


def test_an_alias_that_could_not_be_tested_is_no_finding_and_not_a_clean_bill() -> None:
    """A check that could not look is a coverage matter: the rule has nothing to read."""
    previous = dns("vendor.github.io", addresses=())
    outcome = run_takeover(Web(), previous)
    assert outcome.status == "skipped"
    assert fire("TAKEOVER_LIKELY", facts(previous, outcome)) == []


def test_a_host_without_a_takeover_result_is_no_finding_whatever_its_dns_says() -> None:
    """Scans from before the check existed have no such result."""
    previous = dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    assert fire("TAKEOVER_LIKELY", host(HOST, dns=previous)) == []


def test_a_host_that_is_not_an_alias_is_no_finding() -> None:
    assert fire("TAKEOVER_LIKELY", judged(Web(), dns())) == []


# ------------------------------------------------------------------------------ DANGLING_CNAME


def test_the_dangling_rule_leaves_a_registrable_name_to_the_takeover_rule() -> None:
    previous = dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    subject = judged(Web(), previous)
    assert len(fire("TAKEOVER_LIKELY", subject)) == 1
    assert fire("DANGLING_CNAME", subject) == []  # one finding for one problem


def test_the_dangling_rule_still_speaks_for_a_name_it_cannot_judge() -> None:
    previous = dns("gone.somewhere.example", addresses=(), dangling=True)
    subject = judged(Web(), previous)
    draft = one("DANGLING_CNAME", subject)
    assert (draft.severity, draft.confidence) == ("medium", "low")
    assert fire("TAKEOVER_LIKELY", subject) == []


def test_the_dangling_rule_works_without_a_takeover_result() -> None:
    previous = dns("gone.somewhere.example", addresses=(), dangling=True)
    assert one("DANGLING_CNAME", host(HOST, dns=previous)).params["target"] == (
        "gone.somewhere.example"
    )


def test_the_rule_texts_are_documented_and_versioned() -> None:
    takeover, dangling = RULES["TAKEOVER_LIKELY"], RULES["DANGLING_CNAME"]
    assert takeover.severities == ("high",) and takeover.checks == ("takeover", "dns")
    assert dangling.version == 2 and "TAKEOVER_LIKELY" in dangling.trigger
    assert set(takeover.labels) >= {"service", "target", "takeover_how", "takeover_claim"}
