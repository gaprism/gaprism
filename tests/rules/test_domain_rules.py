"""Domain-level rules, over what the domain checks really produce."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from typing import Any

import dns.message
import dns.resolver
import httpx
import pytest

from app.checks.base import CheckOutcome
from tests.checks.test_breaches_check import ADOBE, FakeLimiters, answering
from tests.checks.test_breaches_check import run as run_breaches
from tests.checks.test_dns_check import TIMEOUT, answer, rr
from tests.checks.test_domain_dns_check import addresses as ns_addresses
from tests.checks.test_domain_dns_check import healthy as dns_setup
from tests.checks.test_domain_dns_check import ns_records
from tests.checks.test_domain_dns_check import run as run_domain_dns
from tests.checks.test_email_check import mail_domain, policy_site, txt
from tests.checks.test_email_check import run as run_email
from tests.checks.test_registration_check import Registry
from tests.checks.test_registration_check import run as run_registration
from tests.checks.test_securitytxt_check import EXPIRES_RAW, WELL_KNOWN, Web
from tests.checks.test_securitytxt_check import GITHUB as SECURITY_TXT
from tests.checks.test_securitytxt_check import run as run_security
from tests.checks.test_securitytxt_check import text as security_text
from tests.rules.helpers import DOMAIN, NOW, domain_facts, fire, one

EMAIL_RULES = [
    "SPF_MISSING",
    "SPF_PERMISSIVE",
    "SPF_INVALID",
    "DMARC_MISSING",
    "DMARC_POLICY_NONE",
    "DMARC_INVALID",
    "MTA_STS_MISSING",
]


def email(**changes: Any) -> CheckOutcome:
    """The real email check over a well-configured domain, with some records changed.

    A value of ``None`` removes the record; an exception makes the lookup fail.
    """
    script = mail_domain()
    for name, value in changes.items():
        key = {
            "spf": (DOMAIN, "TXT"),
            "dmarc": (f"_dmarc.{DOMAIN}", "TXT"),
            "mx": (DOMAIN, "MX"),
            "mta_sts": (f"_mta-sts.{DOMAIN}", "TXT"),
        }[name]
        if value is None:
            script.pop(key, None)
        elif isinstance(value, str):
            script[key] = txt(key[0], value)
        else:
            script[key] = value
    return run_email(script, policy_site)[0]


def everything(facts: Any) -> dict[str, Any]:
    return {rid: fire(rid, facts) for rid in EMAIL_RULES if fire(rid, facts)}


@pytest.fixture(autouse=True)
def quick_hibp(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr("app.checks.breaches.LIMITERS", FakeLimiters())
    yield


NULL_MX = answer(DOMAIN, "MX", rr(DOMAIN, 300, "MX", "0 ."))


# ------------------------------------------------------------------------------ email


def test_a_well_configured_domain_raises_no_email_findings() -> None:
    assert everything(domain_facts(email=email())) == {}


def test_a_check_that_failed_gives_the_email_rules_nothing_to_judge() -> None:
    facts = domain_facts(email=CheckOutcome("error", "timeout"))
    assert everything(facts) == {}


def test_spf_missing_is_medium_for_a_mail_domain_and_low_for_one_without_mail() -> None:
    with_mail = one("SPF_MISSING", domain_facts(email=email(spf="google-site-verification=x")))
    assert (with_mail.severity, with_mail.confidence, with_mail.attribution) == (
        "medium",
        "high",
        "domain",
    )
    no_mail = one("SPF_MISSING", domain_facts(email=email(spf=None, mx=NULL_MX)))
    assert no_mail.severity == "low"
    assert no_mail.subject == f"domain:{DOMAIN}" and len(no_mail.evidence) == 1


def test_an_spf_lookup_that_failed_is_not_a_missing_spf() -> None:
    assert fire("SPF_MISSING", domain_facts(email=email(spf=TIMEOUT))) == []


@pytest.mark.parametrize(
    ("record", "severity", "confidence", "ending"),
    [
        ("v=spf1 +all", "high", "high", "+all"),
        ("v=spf1 all", "high", "high", "+all"),
        ("v=spf1 include:_spf.google.com ?all", "medium", "medium", "?all"),
        ("v=spf1 ip4:192.0.2.1", "medium", "medium", "no all term"),
    ],
)
def test_an_spf_record_that_does_not_restrict_senders(
    record: str, severity: str, confidence: str, ending: str
) -> None:
    draft = one("SPF_PERMISSIVE", domain_facts(email=email(spf=record)))
    assert (draft.severity, draft.confidence, draft.params["ending"]) == (
        severity,
        confidence,
        ending,
    )


@pytest.mark.parametrize(
    "record", ["v=spf1 -all", "v=spf1 include:_spf.google.com ~all", "v=spf1 mx -all"]
)
def test_a_restrictive_spf_record_is_fine(record: str) -> None:
    assert fire("SPF_PERMISSIVE", domain_facts(email=email(spf=record))) == []


def test_a_redirect_to_a_strict_record_is_fine_and_to_an_unreadable_one_is_unknown() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 redirect=_spf.example.net")
    script[("_spf.example.net", "TXT")] = txt("_spf.example.net", "v=spf1 -all")
    facts = domain_facts(email=run_email(script, policy_site)[0])
    assert fire("SPF_PERMISSIVE", facts) == []
    script[("_spf.example.net", "TXT")] = TIMEOUT
    facts = domain_facts(email=run_email(script, policy_site)[0])
    assert fire("SPF_PERMISSIVE", facts) == []  # not known to be permissive


def test_an_spf_record_receivers_cannot_use() -> None:
    two = txt(DOMAIN, "v=spf1 -all", "v=spf1 include:_spf.google.com -all")
    draft = one("SPF_INVALID", domain_facts(email=email(spf=two)))
    assert (draft.severity, draft.params["problems"]) == ("medium", ["multiple_records"])

    script = mail_domain()
    chain = [f"i{n}.example.net" for n in range(20)]
    script[(DOMAIN, "TXT")] = txt(DOMAIN, f"v=spf1 include:{chain[0]} -all")
    for here, there in zip(chain, [*chain[1:], "end.example.net"], strict=True):
        script[(here, "TXT")] = txt(here, f"v=spf1 include:{there} ~all")
    draft = one("SPF_INVALID", domain_facts(email=run_email(script, policy_site)[0]))
    assert draft.params["problems"] == ["too_many_lookups"] and draft.params["lookups"] > 10


def test_a_valid_spf_record_is_not_invalid() -> None:
    assert fire("SPF_INVALID", domain_facts(email=email())) == []


def test_dmarc_missing_follows_the_same_mail_domain_logic() -> None:
    mail = one("DMARC_MISSING", domain_facts(email=email(dmarc=None)))
    assert (mail.severity, mail.confidence) == ("medium", "high")
    assert one("DMARC_MISSING", domain_facts(email=email(dmarc=None, mx=NULL_MX))).severity == "low"
    assert fire("DMARC_MISSING", domain_facts(email=email(dmarc=TIMEOUT))) == []  # unknown


def test_a_dmarc_policy_of_none_is_low_and_names_the_report_address() -> None:
    draft = one(
        "DMARC_POLICY_NONE",
        domain_facts(email=email(dmarc="v=DMARC1; p=none; rua=mailto:r@example.com")),
    )
    assert (draft.severity, draft.params["rua"]) == ("low", ["mailto:r@example.com"])
    for policy in ("quarantine", "reject"):
        facts = domain_facts(email=email(dmarc=f"v=DMARC1; p={policy}"))
        assert fire("DMARC_POLICY_NONE", facts) == []


def test_a_broken_dmarc_record_is_medium() -> None:
    bad = one("DMARC_INVALID", domain_facts(email=email(dmarc="v=DMARC1; p=banana")))
    assert (bad.severity, bad.params["problems"]) == ("medium", ["invalid_policy"])
    two = txt(f"_dmarc.{DOMAIN}", "v=DMARC1; p=reject", "v=DMARC1; p=none")
    assert one("DMARC_INVALID", domain_facts(email=email(dmarc=two))).severity == "medium"
    assert fire("DMARC_INVALID", domain_facts(email=email(dmarc="v=DMARC1; p=reject"))) == []


def test_mta_sts_is_only_asked_of_domains_that_receive_mail() -> None:
    assert (
        one("MTA_STS_MISSING", domain_facts(email=email(mta_sts=None))).severity == "informational"
    )
    assert fire("MTA_STS_MISSING", domain_facts(email=email(mta_sts=None, mx=NULL_MX))) == []
    assert fire("MTA_STS_MISSING", domain_facts(email=email())) == []


# ------------------------------------------------------------------------------ registration


def registration(domain: str = "example.com", **data_changes: Any) -> CheckOutcome:
    outcome = run_registration(domain, Registry())
    outcome.data.update(data_changes)
    return outcome


def test_dnssec_that_is_off_is_informational_and_unknown_is_not_judged() -> None:
    assert one(
        "DNSSEC_NOT_ENABLED", domain_facts(registration=registration(dnssec=False))
    ).severity == ("informational")
    for state in (True, None):
        assert (
            fire("DNSSEC_NOT_ENABLED", domain_facts(registration=registration(dnssec=state))) == []
        )


@pytest.mark.parametrize(
    ("days", "severity"), [(29, "medium"), (0, "medium"), (-1, "high"), (-400, "high")]
)
def test_a_domain_about_to_run_out_or_already_out(days: int, severity: str) -> None:
    draft = one("DOMAIN_EXPIRES_SOON", domain_facts(registration=registration(days_to_expiry=days)))
    assert (draft.severity, draft.params["days"]) == (severity, days)


@pytest.mark.parametrize("days", [30, 311, None])
def test_a_domain_with_time_left_or_no_published_date_is_not_expiring(days: int | None) -> None:
    assert (
        fire("DOMAIN_EXPIRES_SOON", domain_facts(registration=registration(days_to_expiry=days)))
        == []
    )


@pytest.mark.parametrize(
    ("age", "fires"), [(0, True), (89, True), (90, False), (4000, False), (None, False)]
)
def test_a_young_domain_is_noted(age: int | None, fires: bool) -> None:
    drafts = fire(
        "DOMAIN_RECENTLY_REGISTERED", domain_facts(registration=registration(age_days=age))
    )
    assert bool(drafts) is fires
    if fires:
        assert drafts[0].severity == "informational" and drafts[0].params["age"] == age


def test_a_missing_transfer_lock_is_only_judged_where_the_registry_has_locks() -> None:
    unlocked = registration(statuses=["client delete prohibited", "ok"], transfer_locked=False)
    draft = one("DOMAIN_NOT_LOCKED", domain_facts(registration=unlocked))
    assert (draft.severity, draft.confidence) == ("low", "medium")
    assert fire("DOMAIN_NOT_LOCKED", domain_facts(registration=registration())) == []  # locked
    swiss = registration("admin.ch")  # the .ch registry only says "active"
    assert fire("DOMAIN_NOT_LOCKED", domain_facts(registration=swiss)) == []
    assert fire("DOMAIN_NOT_LOCKED", domain_facts(registration=registration(statuses=[]))) == []


def test_the_real_registry_answers_raise_no_expiry_or_age_findings() -> None:
    facts = domain_facts(registration=registration("github.com"))
    for rule in ("DOMAIN_EXPIRES_SOON", "DOMAIN_RECENTLY_REGISTERED", "DOMAIN_NOT_LOCKED"):
        assert fire(rule, facts) == []
    assert len(fire("DNSSEC_NOT_ENABLED", facts)) == 1  # github.com is not signed


# ------------------------------------------------------------------------------ breaches


def breach(**fields: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "Name": "ExampleBreach",
        "Title": "Example Breach",
        "Domain": DOMAIN,
        "BreachDate": "2026-01-01",
        "AddedDate": "2026-01-05T00:00:00Z",
        "PwnCount": 1234,
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
    }
    values.update(fields)
    return values


def breaches(*items: dict[str, Any], domain: str = DOMAIN) -> CheckOutcome:
    return run_breaches(answering(list(items)), domain)


def test_an_old_documented_breach_is_medium_and_a_recent_one_high() -> None:
    old = one(
        "PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(breach(BreachDate="2013-10-04")))
    )
    assert (old.severity, old.confidence) == ("medium", "high")
    recent = one(
        "PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(breach(BreachDate="2025-12-01")))
    )
    assert (recent.severity, recent.params["months_ago"]) == ("high", 10)


@pytest.mark.parametrize(
    ("date", "months", "severity"),
    [
        ("2024-10-05", 24, "high"),  # exactly 24 months before the fixed "now": still recent
        ("2024-09-01", 25, "medium"),
        ("2026-10-05", 6, "high"),
        ("2020-01-01", 24, "medium"),
        ("2026-01-01", 6, "medium"),  # nine months ago is not recent when recent means six
    ],
)
def test_recent_means_within_the_configured_number_of_months(
    date: str, months: int, severity: str
) -> None:
    facts = domain_facts(breaches=breaches(breach(BreachDate=date)))
    assert one("PUBLIC_BREACH_HISTORY", facts, breach_recent_months=months).severity == severity


def test_a_breach_without_a_usable_date_is_medium_with_low_confidence() -> None:
    draft = one("PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(breach(BreachDate="?"))))
    assert (draft.severity, draft.confidence, draft.params["months_ago"]) == ("medium", "low", None)


def test_unverified_breaches_are_less_certain() -> None:
    draft = one("PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(breach(IsVerified=False))))
    assert draft.confidence == "medium"


@pytest.mark.parametrize("flag", ["IsFabricated", "IsSpamList", "IsRetired"])
def test_fabricated_spam_and_retired_entries_are_ignored(flag: str) -> None:
    facts = domain_facts(breaches=breaches(breach(**{flag: True})))
    assert fire("PUBLIC_BREACH_HISTORY", facts) == []


def test_a_breach_of_another_services_domain_is_not_this_vendors() -> None:
    elsewhere = breach(Domain="someone-else.example")
    assert fire("PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(elsewhere))) == []
    sub = breach(Name="Sub", Domain=f"shop.{DOMAIN}")
    assert len(fire("PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(sub)))) == 1


def test_every_breach_is_its_own_finding_so_each_can_be_accepted_alone() -> None:
    items = (
        breach(Name="One", BreachDate="2020-01-01"),
        breach(Name="Two", BreachDate="2026-06-01"),
    )
    drafts = fire("PUBLIC_BREACH_HISTORY", domain_facts(breaches=breaches(*items)))
    assert sorted(d.subject for d in drafts) == [
        f"domain:{DOMAIN}:breach:One",
        f"domain:{DOMAIN}:breach:Two",
    ]
    assert {d.params["name"]: d.severity for d in drafts} == {"One": "medium", "Two": "high"}


def test_the_real_adobe_breach_and_no_breach() -> None:
    adobe = run_breaches(answering(ADOBE), "adobe.com")
    draft = one("PUBLIC_BREACH_HISTORY", domain_facts("adobe.com", breaches=adobe))
    assert (draft.severity, draft.params["accounts"], draft.params["breach_date"]) == (
        "medium",
        152445165,
        "2013-10-04",
    )
    none = run_breaches(answering([]))
    assert (
        fire("PUBLIC_BREACH_HISTORY", domain_facts(breaches=none)) == []
    )  # no_data: nothing to judge


# ------------------------------------------------------------------------------ security.txt


def security(files: dict[tuple[str, str], Any] | None = None, **replace: str) -> CheckOutcome:
    body = SECURITY_TXT
    for old, new in replace.items():
        body = body.replace(old.replace("_", " "), new)
    return run_security(Web(files or {("example.com", WELL_KNOWN): security_text(body)}))


def test_no_security_txt_is_informational() -> None:
    draft = one("SECURITY_TXT_MISSING", domain_facts(security_txt=run_security(Web())))
    assert (draft.severity, draft.confidence) == ("informational", "medium")


def test_a_security_txt_that_could_not_be_looked_for_is_not_a_missing_one() -> None:
    errored = run_security(
        Web(
            {
                (h, p): httpx.ReadTimeout("x")
                for h in ("example.com", "www.example.com")
                for p in (WELL_KNOWN, "/security.txt")
            }
        )
    )
    assert errored.status == "error"
    assert fire("SECURITY_TXT_MISSING", domain_facts(security_txt=errored)) == []


def test_a_security_txt_that_is_unusable() -> None:
    old = SECURITY_TXT.replace(EXPIRES_RAW, "2020-01-01T00:00:00Z")
    expired = run_security(Web({("example.com", WELL_KNOWN): security_text(old)}))
    draft = one("SECURITY_TXT_INVALID", domain_facts(security_txt=expired))
    assert (draft.severity, "expired" in draft.params["problems"]) == ("low", True)

    no_contact = security_text(
        "Expires: 2030-01-01T00:00:00Z\nPolicy: https://example.com/policy\n"
    )
    outcome = run_security(Web({("example.com", WELL_KNOWN): no_contact}))
    assert one("SECURITY_TXT_INVALID", domain_facts(security_txt=outcome)).params["problems"] == [
        "missing_contact"
    ]


def test_style_problems_alone_do_not_make_a_security_txt_unusable() -> None:
    style = security_text(
        SECURITY_TXT, "text/html"
    )  # served as the wrong type, canonical elsewhere
    outcome = run_security(Web({("example.com", WELL_KNOWN): style}))
    assert {"not_plain_text", "canonical_mismatch"} <= set(outcome.data["problems"])
    assert fire("SECURITY_TXT_INVALID", domain_facts(security_txt=outcome)) == []
    assert fire("SECURITY_TXT_MISSING", domain_facts(security_txt=outcome)) == []


# ------------------------------------------------------------------------------ DNS set-up


def test_no_caa_is_informational() -> None:
    script = dns_setup()
    del script[("example.com", "CAA")]
    outcome = run_domain_dns(script)[0]
    assert one("CAA_MISSING", domain_facts(domain_dns=outcome)).severity == "informational"
    assert fire("CAA_MISSING", domain_facts(domain_dns=run_domain_dns(dns_setup())[0])) == []


def test_caa_that_could_not_be_read_is_not_missing() -> None:
    script = dns_setup()
    script[("example.com", "CAA")] = TIMEOUT
    assert fire("CAA_MISSING", domain_facts(domain_dns=run_domain_dns(script)[0])) == []


def ns_script(*servers: tuple[str, str]) -> dict[tuple[str, str], Any]:
    script: dict[tuple[str, str], Any] = {
        ("example.com", "NS"): ns_records("example.com", *[h for h, _ in servers])
    }
    for host_name, ip in servers:
        script.update(ns_addresses(host_name, ip))
    return script


def test_name_server_problems_by_severity() -> None:
    one_server = run_domain_dns(ns_script(("ns1.a.net", "198.51.100.1")))[0]
    assert one("NS_NOT_REDUNDANT", domain_facts(domain_dns=one_server)).severity == "medium"

    same_net = run_domain_dns(
        ns_script(("ns1.a.net", "198.51.100.1"), ("ns2.b.org", "198.51.100.9"))
    )[0]
    draft = one("NS_NOT_REDUNDANT", domain_facts(domain_dns=same_net))
    assert (draft.severity, draft.params["problems"]) == ("low", ["single_network"])

    script = ns_script(("ns1.a.net", "198.51.100.1"))
    script[("example.com", "NS")] = ns_records("example.com", "ns1.a.net", "ns2.b.org")
    unresolved = run_domain_dns(script)[0]
    assert (
        "unresolvable"
        in one("NS_NOT_REDUNDANT", domain_facts(domain_dns=unresolved)).params["problems"]
    )


def test_one_dns_operator_alone_is_not_a_finding() -> None:
    script = ns_script(("ns1.example.com", "198.51.100.1"), ("ns2.example.com", "203.0.113.1"))
    outcome = run_domain_dns(script)[0]
    assert outcome.data["ns"]["single_operator"] is True
    assert fire("NS_NOT_REDUNDANT", domain_facts(domain_dns=outcome)) == []


def test_a_healthy_dns_set_up_and_one_that_could_not_be_read() -> None:
    assert fire("NS_NOT_REDUNDANT", domain_facts(domain_dns=run_domain_dns(dns_setup())[0])) == []
    script = dns_setup()
    script[("example.com", "NS")] = dns.resolver.NoNameservers(
        request=dns.message.make_query("example.com", "NS"), errors=[]
    )
    broken = run_domain_dns(script)[0]
    assert fire("NS_NOT_REDUNDANT", domain_facts(domain_dns=broken)) == []


def test_the_facts_are_not_modified_by_the_rules() -> None:
    outcome = email()
    before = copy.deepcopy(outcome.data)
    facts = domain_facts(email=outcome)
    for rule_id in EMAIL_RULES:
        fire(rule_id, facts)
    assert outcome.data == before
    assert NOW.year == 2026
