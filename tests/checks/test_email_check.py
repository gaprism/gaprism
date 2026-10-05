"""The email check: real dnspython answers from a scripted resolver, a mock HTTPS transport."""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

import dns.message
import dns.resolver
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import ResolverLike
from app.checks.email import (
    DKIM_SELECTORS,
    MAX_SPF_FETCHES,
    MAX_SPF_TERMS,
    EmailCheck,
    dkim_key,
    is_spf,
    parse_dmarc,
    parse_mta_sts_policy,
    parse_spf,
    parse_tags,
)
from runner.egress import EgressHTTPClient
from tests.checks.test_dns_check import CONFIG, TIMEOUT, ScriptedResolver, answer, rr

DOMAIN = "example.com"
POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 86400\n"


def txt(name: str, *values: str) -> dns.resolver.Answer:
    """TXT records; a long value is split into strings of at most 250 characters, as in real DNS."""
    lines = []
    for value in values:
        chunks = " ".join(f'"{value[i : i + 250]}"' for i in range(0, len(value), 250))
        lines.append(rr(name, 300, "TXT", chunks))
    return answer(name, "TXT", *lines)


def public_key_record(private: Any) -> str:
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


RSA_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# A weak key on purpose: the check must recognise and report it.
RSA_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505


# ------------------------------------------------------------------------------ parsers


def test_tags_are_read_leniently_and_the_first_occurrence_wins() -> None:
    assert parse_tags("v=DMARC1; P=reject ;; rua=mailto:a@x.example; p=none; =x; junk") == {
        "v": "DMARC1",
        "p": "reject",
        "rua": "mailto:a@x.example",
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v=spf1 -all", True),
        ("  V=SPF1 include:x.example ~all", True),
        ("v=spf1", True),
        ("v=spf10 -all", False),
        ("spf2.0/pra ip4:1.2.3.4 -all", False),
        ("google-site-verification=abc", False),
        ("", False),
    ],
)
def test_which_txt_values_are_spf_records(text: str, expected: bool) -> None:
    assert is_spf(text) is expected


@pytest.mark.parametrize(
    ("record", "final", "lookups", "includes", "redirect", "problems"),
    [
        ("v=spf1 include:_spf.google.com ~all", "softfail", 1, ["_spf.google.com"], None, []),
        ("v=spf1 a mx ip4:192.0.2.0/24 ip6:2001:db8::/32 -all", "fail", 2, [], None, []),
        ("v=spf1 redirect=_spf.example.net", None, 1, [], "_spf.example.net", []),
        ("v=spf1 +all", "pass", 0, [], None, []),
        ("v=spf1 all", "pass", 0, [], None, []),  # no qualifier means "+"
        ("v=spf1 ?all", "neutral", 0, [], None, []),
        ("v=spf1 ptr -all", "fail", 1, [], None, ["ptr_used"]),
        ("v=spf1 foo:bar -all", "fail", 0, [], None, ["unknown_term"]),
        ("v=spf1 exists:%{i}.bl.example.net a:host.example.com/24 -all", "fail", 2, [], None, []),
        ("v=spf1 exp=why.example.com -all", "fail", 0, [], None, []),  # exp is not a lookup
        ("v=spf1 colour=red -all", "fail", 0, [], None, ["unknown_modifier"]),
        ("v=spf1 INCLUDE:Mail.Example.NET. -ALL", "fail", 1, ["mail.example.net"], None, []),
        ("v=spf1", None, 0, [], None, []),
    ],
)
def test_spf_records_are_parsed_with_their_lookups(
    record: str,
    final: str | None,
    lookups: int,
    includes: list[str],
    redirect: str | None,
    problems: list[str],
) -> None:
    parsed = parse_spf(record)
    assert parsed["all"] == final and parsed["direct_lookups"] == lookups
    assert parsed["includes"] == includes and parsed["redirect"] == redirect
    assert parsed["problems"] == problems


def test_an_absurdly_long_spf_record_is_bounded() -> None:
    parsed = parse_spf("v=spf1 " + " ".join(f"ip4:10.0.{n % 250}.1" for n in range(500)) + " -all")
    assert len(parsed["terms"]) <= MAX_SPF_TERMS


def test_dmarc_tags_become_a_policy() -> None:
    parsed = parse_dmarc(
        "v=DMARC1; p=Reject; sp=quarantine; pct=50; rua=mailto:a@x.example, https://r.example/x;"
        " ruf=mailto:f@x.example; adkim=s; aspf=R"
    )
    assert parsed == {
        "policy": "reject",
        "subdomain_policy": "quarantine",
        "pct": 50,
        "rua": ["mailto:a@x.example", "https://r.example/x"],
        "ruf": ["mailto:f@x.example"],
        "adkim": "s",
        "aspf": "r",
        "problems": [],
    }


@pytest.mark.parametrize(
    ("record", "field", "value", "problem"),
    [
        ("v=DMARC1; p=banana", "policy", None, "invalid_policy"),
        ("v=DMARC1", "policy", None, "invalid_policy"),  # p is required
        ("v=DMARC1; p=none; sp=maybe", "subdomain_policy", None, "invalid_subdomain_policy"),
        ("v=DMARC1; p=none; pct=lots", "pct", None, "invalid_pct"),
        ("v=DMARC1; p=none; pct=250", "pct", None, "invalid_pct"),
    ],
)
def test_a_bad_dmarc_record_is_reported_not_guessed(
    record: str, field: str, value: object, problem: str
) -> None:
    parsed = parse_dmarc(record)
    assert parsed[field] == value and problem in parsed["problems"]


def test_the_defaults_of_dmarc_are_applied() -> None:
    parsed = parse_dmarc("v=DMARC1; p=none")
    assert (parsed["pct"], parsed["adkim"], parsed["aspf"], parsed["rua"]) == (100, "r", "r", [])


def test_dkim_key_sizes_are_read_from_the_record() -> None:
    record = f"v=DKIM1; k=rsa; p={public_key_record(RSA_2048)}"
    assert dkim_key(record) == {"key_type": "rsa", "bits": 2048, "revoked": False, "testing": False}
    spaced = public_key_record(RSA_1024)
    spaced = " ".join(spaced[i : i + 40] for i in range(0, len(spaced), 40))  # as split in DNS
    assert dkim_key(f"v=DKIM1; p={spaced}; t=y:s")["bits"] == 1024
    assert dkim_key(f"v=DKIM1; p={spaced}; t=y:s")["testing"] is True
    ed = ed25519.Ed25519PrivateKey.generate()
    assert dkim_key(f"v=DKIM1; k=ed25519; p={public_key_record(ed)}")["bits"] == 256
    assert dkim_key("v=DKIM1; k=rsa; p=")["revoked"] is True  # an empty key revokes the selector
    assert dkim_key("v=DKIM1; p=not-base64-at-all!!")["bits"] is None
    assert dkim_key("v=DKIM1; p=AAAA")["bits"] is None  # valid base64, not a key


def test_an_mta_sts_policy_is_read() -> None:
    assert parse_mta_sts_policy(POLICY) == {
        "valid": True,
        "mode": "enforce",
        "mx": ["mail.example.com", "*.example.net"],
        "max_age": 86400,
    }
    assert parse_mta_sts_policy("version: STSv2\nmode: enforce")["valid"] is False
    assert parse_mta_sts_policy("version: STSv1\nmode: maybe")["valid"] is False
    assert parse_mta_sts_policy("garbage")["valid"] is False


# ------------------------------------------------------------------------------ the check


def web(handler: Callable[[httpx.Request], httpx.Response]) -> Callable[..., EgressHTTPClient]:
    """A client factory whose HTTPS goes to ``handler`` and whose names resolve to a public IP."""

    def factory(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            custom_transport=httpx.MockTransport(handler),
            resolver_fn=lambda name: ["93.184.216.34"],
        )

    return factory


def no_web(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected request to {request.url}")


def run(
    script: dict[tuple[str, str], Any],
    handler: Callable[[httpx.Request], httpx.Response] = no_web,
    clock: Callable[[], float] | None = None,
) -> tuple[CheckOutcome, ScriptedResolver]:
    resolver = ScriptedResolver(script)

    def factory(_config: Any) -> ResolverLike:
        return resolver

    kwargs: dict[str, Any] = {"clock": clock} if clock else {}
    check = EmailCheck(
        resolver_factory=factory,
        client_factory=web(handler),
        name_resolver=lambda config, name: ["93.184.216.34"],
        **kwargs,
    )
    ctx = CheckContext(domain=DOMAIN, hostname=None, config=CONFIG, http=httpx.Client())
    return check.run(ctx), resolver


def mail_domain() -> dict[tuple[str, str], Any]:
    """A domain on Google Workspace with SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI."""
    d = DOMAIN
    return {
        (d, "MX"): answer(
            d,
            "MX",
            rr(d, 300, "MX", "1 aspmx.l.google.com."),
            rr(d, 300, "MX", "5 alt1.aspmx.l.google.com."),
        ),
        (d, "TXT"): txt(d, "google-site-verification=abc", "v=spf1 include:_spf.google.com -all"),
        ("_spf.google.com", "TXT"): txt(
            "_spf.google.com", "v=spf1 include:_netblocks.google.com ~all"
        ),
        ("_netblocks.google.com", "TXT"): txt(
            "_netblocks.google.com", "v=spf1 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ~all"
        ),
        (f"_dmarc.{d}", "TXT"): txt(
            f"_dmarc.{d}", "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"
        ),
        (f"google._domainkey.{d}", "TXT"): txt(
            f"google._domainkey.{d}", f"v=DKIM1; k=rsa; p={public_key_record(RSA_2048)}"
        ),
        (f"_mta-sts.{d}", "TXT"): txt(f"_mta-sts.{d}", "v=STSv1; id=20260901T000000"),
        (f"_smtp._tls.{d}", "TXT"): txt(
            f"_smtp._tls.{d}", "v=TLSRPTv1; rua=mailto:tls@example.com"
        ),
        (f"default._bimi.{d}", "TXT"): txt(
            f"default._bimi.{d}", "v=BIMI1; l=https://example.com/logo.svg;"
        ),
    }


def policy_site(request: httpx.Request) -> httpx.Response:
    assert request.headers["host"] == f"mta-sts.{DOMAIN}"
    assert request.url.path == "/.well-known/mta-sts.txt"
    return httpx.Response(200, text=POLICY, headers={"content-type": "text/plain"})


def test_a_fully_configured_domain_is_read_completely() -> None:
    outcome, _ = run(mail_domain(), policy_site)

    assert outcome.status == "ok" and outcome.source == "dns:1.1.1.1,8.8.8.8"
    data = outcome.data
    assert data["domain"] == DOMAIN and data["errors"] == {}

    assert data["mx"]["found"] is True and data["mx"]["null_mx"] is False
    assert [r["host"] for r in data["mx"]["records"]] == [
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
    ]
    assert data["mx"]["providers"] == ["Google Workspace"]

    spf = data["spf"]
    assert (spf["found"], spf["qualifier"], spf["count"]) == (True, "fail", 1)
    assert spf["includes"] == ["_spf.google.com"] and spf["senders"] == ["Google Workspace"]
    # the top-level include, plus the include inside _spf.google.com; ip4 terms cost nothing
    assert (spf["lookups"], spf["lookups_complete"], spf["problems"]) == (2, True, [])

    dmarc = data["dmarc"]
    assert dmarc["found"] is True and (dmarc["policy"], dmarc["pct"]) == ("reject", 100)
    assert dmarc["rua"] == ["mailto:dmarc@example.com"] and dmarc["problems"] == []

    assert data["dkim"]["found"] == [
        {"selector": "google", "key_type": "rsa", "bits": 2048, "revoked": False, "testing": False}
    ]
    assert data["dkim"]["selectors_checked"] == list(DKIM_SELECTORS)
    assert data["dkim"]["error"] is None and data["dkim"]["incomplete"] is False

    sts = data["mta_sts"]
    assert sts["found"] is True and sts["id"] == "20260901T000000"
    assert sts["policy"]["fetched"] is True and sts["policy"]["error"] is None
    assert (sts["policy"]["mode"], sts["policy"]["max_age"]) == ("enforce", 86400)

    assert data["tls_rpt"]["rua"] == ["mailto:tls@example.com"]
    assert data["bimi"]["logo"] == "https://example.com/logo.svg"


def test_a_domain_without_any_mail_records_is_ok_with_absences_stated() -> None:
    outcome, _ = run({})  # every question is answered "no such record"
    assert outcome.status == "ok"
    data = outcome.data
    assert data["mx"] == {"found": False, "null_mx": False, "records": [], "providers": []}
    assert data["spf"] == {"found": False}
    assert (data["dmarc"], data["mta_sts"], data["tls_rpt"], data["bimi"]) == (
        {"found": False},
        {"found": False},
        {"found": False},
        {"found": False},
    )
    assert data["dkim"]["found"] == []  # "none found", which is not "none exist"
    assert len(data["dkim"]["selectors_checked"]) == len(DKIM_SELECTORS)
    assert data["errors"] == {}


def test_a_null_mx_means_the_domain_does_not_receive_mail() -> None:
    d = DOMAIN
    outcome, _ = run({(d, "MX"): answer(d, "MX", rr(d, 300, "MX", "0 ."))})
    assert outcome.data["mx"] == {"found": False, "null_mx": True, "records": [], "providers": []}


def test_a_domain_that_does_not_exist_is_no_data() -> None:
    outcome, _ = run({(DOMAIN, "MX"): dns.resolver.NXDOMAIN()})
    assert (outcome.status, outcome.reason_code) == ("no_data", "nxdomain")


def test_an_unreachable_resolver_is_an_error_after_two_questions() -> None:
    outcome, resolver = run({(DOMAIN, "MX"): TIMEOUT, (DOMAIN, "TXT"): TIMEOUT})
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")
    assert resolver.calls == [(DOMAIN, "MX"), (DOMAIN, "TXT")]  # nothing else was attempted


def test_a_part_that_could_not_be_asked_says_so_instead_of_looking_absent() -> None:
    script = mail_domain()
    script[(f"_dmarc.{DOMAIN}", "TXT")] = TIMEOUT
    script[(f"_smtp._tls.{DOMAIN}", "TXT")] = dns.resolver.NoNameservers(
        request=dns.message.make_query(f"_smtp._tls.{DOMAIN}", "TXT"), errors=[]
    )
    outcome, _ = run(script, policy_site)

    assert outcome.status == "ok"
    assert outcome.data["dmarc"] == {"found": None, "error": "timeout"}
    assert outcome.data["tls_rpt"] == {"found": None, "error": "servfail"}
    assert outcome.data["errors"] == {"dmarc": "timeout", "tls_rpt": "servfail"}
    assert outcome.data["spf"]["found"] is True  # the rest is unaffected


def test_an_spf_lookup_error_makes_the_count_incomplete() -> None:
    script = mail_domain()
    script[("_spf.google.com", "TXT")] = TIMEOUT
    outcome, _ = run(script, policy_site)
    spf = outcome.data["spf"]
    assert spf["lookups_complete"] is False and spf["lookups"] == 1  # only the top level is known


def test_two_spf_records_are_a_problem() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 -all", "v=spf1 include:_spf.google.com -all")
    outcome, _ = run(script, policy_site)
    spf = outcome.data["spf"]
    assert spf["count"] == 2 and "multiple_records" in spf["problems"]
    assert spf["record"] == "v=spf1 -all"  # the first is shown; evaluators would fail on both


def test_two_dmarc_records_are_a_problem_and_the_parsers_findings_do_not_replace_it() -> None:
    script = mail_domain()
    script[(f"_dmarc.{DOMAIN}", "TXT")] = txt(
        f"_dmarc.{DOMAIN}", "v=DMARC1; p=banana", "v=DMARC1; p=reject"
    )
    dmarc = run(script, policy_site)[0].data["dmarc"]
    assert dmarc["count"] == 2
    assert dmarc["problems"] == ["multiple_records", "invalid_policy"]  # both are kept


def test_an_spf_record_without_all_or_redirect_is_flagged() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 ip4:192.0.2.1")
    outcome, _ = run(script, policy_site)
    spf = outcome.data["spf"]
    assert spf["qualifier"] is None and "no_all" in spf["problems"]


def test_a_redirect_supplies_the_policy_and_counts_as_a_lookup() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 redirect=_spf.example.net")
    script[("_spf.example.net", "TXT")] = txt("_spf.example.net", "v=spf1 mx a -all")
    outcome, _ = run(script, policy_site)
    spf = outcome.data["spf"]
    assert (spf["redirect"], spf["lookups"], "no_all" in spf["problems"]) == (
        "_spf.example.net",
        3,  # the redirect, mx and a
        False,
    )
    assert (spf["qualifier"], spf["qualifier_via"]) == ("fail", "redirect")  # the target decides


def test_the_verdict_of_a_chain_of_redirects_is_found() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 redirect=a.example.net")
    script[("a.example.net", "TXT")] = txt("a.example.net", "v=spf1 redirect=b.example.net")
    script[("b.example.net", "TXT")] = txt("b.example.net", "v=spf1 ip4:192.0.2.1 ~all")
    spf = run(script, policy_site)[0].data["spf"]
    assert (spf["qualifier"], spf["qualifier_via"], spf["problems"]) == ("softfail", "redirect", [])


def test_a_redirect_that_ends_without_all_is_flagged() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 redirect=a.example.net")
    script[("a.example.net", "TXT")] = txt("a.example.net", "v=spf1 ip4:192.0.2.1")
    spf = run(script, policy_site)[0].data["spf"]
    assert spf["qualifier"] is None and "no_all" in spf["problems"]


def test_a_redirect_that_cannot_be_read_is_unknown_not_a_problem() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 redirect=a.example.net")
    script[("a.example.net", "TXT")] = TIMEOUT
    spf = run(script, policy_site)[0].data["spf"]
    assert spf["qualifier"] is None and spf["lookups_complete"] is False
    assert "no_all" not in spf["problems"]  # we do not know that it lacks one


def test_a_redirect_is_ignored_when_the_record_has_an_all_term() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 -all redirect=a.example.net")
    script[("a.example.net", "TXT")] = txt("a.example.net", "v=spf1 +all")
    spf = run(script, policy_site)[0].data["spf"]
    assert (spf["qualifier"], spf["qualifier_via"]) == ("fail", None)  # RFC 7208 6.1


def test_more_than_ten_lookups_are_reported_and_following_includes_is_bounded() -> None:
    script = mail_domain()
    chain = [f"i{n}.example.net" for n in range(20)]
    script[(DOMAIN, "TXT")] = txt(DOMAIN, f"v=spf1 include:{chain[0]} -all")
    for here, there in zip(chain, [*chain[1:], "end.example.net"], strict=True):
        script[(here, "TXT")] = txt(here, f"v=spf1 include:{there} ~all")
    outcome, resolver = run(script, policy_site)

    spf = outcome.data["spf"]
    assert "too_many_lookups" in spf["problems"] and spf["lookups"] > 10
    assert spf["lookups_complete"] is False  # the walk stopped at its budget
    spf_fetches = [call for call in resolver.calls if call[0].endswith(".example.net")]
    assert len(spf_fetches) == MAX_SPF_FETCHES


def test_an_include_loop_terminates() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 include:a.example.net -all")
    script[("a.example.net", "TXT")] = txt("a.example.net", "v=spf1 include:b.example.net ~all")
    script[("b.example.net", "TXT")] = txt("b.example.net", "v=spf1 include:a.example.net ~all")
    outcome, resolver = run(script, policy_site)
    assert outcome.data["spf"]["lookups"] == 3 and outcome.data["spf"]["lookups_complete"] is True
    assert resolver.calls.count(("a.example.net", "TXT")) == 1


def test_senders_named_in_spf_are_recognised_by_whole_labels() -> None:
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(
        DOMAIN,
        "v=spf1 include:spf.protection.outlook.com include:sendgrid.net"
        " include:evilsendgrid.net include:google.com.evil.example -all",
    )
    outcome, _ = run(script, policy_site)
    assert outcome.data["spf"]["senders"] == ["Microsoft 365", "SendGrid"]


def test_mail_providers_are_recognised_by_whole_labels() -> None:
    d = DOMAIN
    script = {
        (d, "MX"): answer(
            d,
            "MX",
            rr(d, 60, "MX", "10 example-com.mail.protection.outlook.com."),
            rr(d, 60, "MX", "20 mx.notgoogle.com."),
            rr(d, 60, "MX", "30 aspmx.l.google.com.evil.example."),
        )
    }
    outcome, _ = run(script)
    assert outcome.data["mx"]["providers"] == ["Microsoft 365"]


def test_dkim_keys_are_listed_with_their_strength_and_revoked_selectors() -> None:
    d = DOMAIN
    script = mail_domain()
    script[(f"selector1._domainkey.{d}", "TXT")] = txt(
        f"selector1._domainkey.{d}", f"v=DKIM1; k=rsa; p={public_key_record(RSA_1024)}; t=y"
    )
    script[(f"k1._domainkey.{d}", "TXT")] = txt(f"k1._domainkey.{d}", "v=DKIM1; k=rsa; p=")
    script[(f"mail._domainkey.{d}", "TXT")] = txt(f"mail._domainkey.{d}", "not a dkim record")
    outcome, _ = run(script, policy_site)
    found = {entry["selector"]: entry for entry in outcome.data["dkim"]["found"]}
    assert sorted(found) == ["google", "selector1"]  # usable keys, in the order of the list
    assert (found["selector1"]["bits"], found["selector1"]["testing"]) == (1024, True)
    assert outcome.data["dkim"]["revoked"] == ["k1"]  # an empty key is not a usable key


def test_a_zone_that_revokes_every_selector_by_wildcard_has_no_keys() -> None:
    """example.com answers every selector with an empty key (found live): that is "no DKIM"."""
    script = {
        (f"{selector}._domainkey.{DOMAIN}", "TXT"): txt(
            f"{selector}._domainkey.{DOMAIN}", "v=DKIM1; p="
        )
        for selector in DKIM_SELECTORS
    }
    outcome, _ = run(script)
    dkim = outcome.data["dkim"]
    assert dkim["found"] == [] and dkim["revoked"] == list(DKIM_SELECTORS)
    assert dkim["incomplete"] is False and dkim["error"] is None


def test_dkim_stops_asking_when_the_resolver_fails() -> None:
    script = mail_domain()
    script[(f"default._domainkey.{DOMAIN}", "TXT")] = TIMEOUT
    outcome, resolver = run(script, policy_site)
    dkim = outcome.data["dkim"]
    assert dkim["incomplete"] is True and dkim["selectors_checked"] == []
    assert dkim["error"] == "timeout"  # nothing could be checked at all
    asked = [call for call in resolver.calls if "_domainkey" in call[0]]
    assert len(asked) == 1  # not twenty-five timeouts in a row


def test_a_later_dkim_failure_keeps_what_was_found() -> None:
    script = mail_domain()
    script[(f"selector1._domainkey.{DOMAIN}", "TXT")] = TIMEOUT
    outcome, _ = run(script, policy_site)
    dkim = outcome.data["dkim"]
    assert [entry["selector"] for entry in dkim["found"]] == ["google"]
    assert dkim["incomplete"] is True and dkim["error"] is None  # something was checked
    assert "dkim" not in outcome.data["errors"]


def test_the_time_budget_stops_the_remaining_questions() -> None:
    ticks = iter([0.0, 0.0, 0.0] + [1000.0] * 500)  # the budget is gone after the first questions
    outcome, _ = run(mail_domain(), policy_site, clock=lambda: next(ticks))
    data = outcome.data
    assert outcome.status == "ok"
    assert data["dmarc"] == {"found": None, "error": "budget_exceeded"}
    assert data["dkim"]["incomplete"] is True
    assert "dmarc" in data["errors"]


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (lambda request: httpx.Response(404, text="nope"), "http_error"),
        (lambda request: httpx.Response(503), "http_error"),
    ],
)
def test_an_mta_sts_policy_that_cannot_be_fetched_is_an_error_not_an_absence(
    handler: Callable[[httpx.Request], httpx.Response], error: str
) -> None:
    outcome, _ = run(mail_domain(), handler)
    policy = outcome.data["mta_sts"]["policy"]
    assert (policy["fetched"], policy["error"]) == (False, error)
    assert outcome.data["mta_sts"]["found"] is True  # the DNS record is there regardless


def test_an_mta_sts_fetch_timeout_is_typed() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    outcome, _ = run(mail_domain(), slow)
    policy = outcome.data["mta_sts"]["policy"]
    assert (policy["fetched"], policy["error"]) == (False, "timeout")


def test_the_mta_sts_policy_is_only_fetched_when_the_dns_record_exists() -> None:
    script = mail_domain()
    del script[(f"_mta-sts.{DOMAIN}", "TXT")]
    outcome, _ = run(script)  # `no_web` fails the test if a request is made
    assert outcome.data["mta_sts"] == {"found": False}


def test_a_blocked_policy_host_is_never_contacted() -> None:
    """mta-sts.<domain> resolving to a private address must not be connected to."""

    def private(config: Any, resolver_fn: Callable[[str], list[str]]) -> EgressHTTPClient:
        return EgressHTTPClient(
            custom_transport=httpx.MockTransport(no_web), resolver_fn=lambda name: ["10.0.0.5"]
        )

    resolver = ScriptedResolver(mail_domain())
    check = EmailCheck(
        resolver_factory=lambda _config: resolver,
        client_factory=private,
        name_resolver=lambda config, name: ["10.0.0.5"],
    )
    ctx = CheckContext(domain=DOMAIN, hostname=None, config=CONFIG, http=httpx.Client())
    policy = check.run(ctx).data["mta_sts"]["policy"]
    assert (policy["fetched"], policy["error"]) == (False, "blocked_destination")


def test_an_mta_sts_policy_served_with_an_invalid_mode_is_fetched_but_not_valid() -> None:
    def odd(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="version: STSv1\nmode: sometimes\nmax_age: 1\n")

    outcome, _ = run(mail_domain(), odd)
    policy = outcome.data["mta_sts"]["policy"]
    assert policy["fetched"] is True and policy["valid"] is False


def test_everything_is_storable_as_json() -> None:
    import json

    outcome, _ = run(mail_domain(), policy_site)
    json.dumps(outcome.data)
