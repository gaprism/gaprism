"""What the analyst sees per host: table cells, the host page, filters, escaping."""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.checks.tls import outcome_from_probe
from app.models import Assessment, CheckResult, Host, Scan
from app.models.base import utc_now
from app.service import exploits as exploit_data
from app.service import host_view
from app.service import scans as scan_service
from app.service.geo import IpLocation
from app.service.ports import PortFacts, PortService, PortsLookup, Vulnerability
from tests.checks.test_breaches_check import ADOBE, LINKEDIN, FakeLimiters
from tests.checks.test_breaches_check import answering as breaches_answer
from tests.checks.test_breaches_check import run as run_breaches
from tests.checks.test_dns_check import answer, rr
from tests.checks.test_dns_check import run as run_dns
from tests.checks.test_domain_dns_check import healthy as dns_setup
from tests.checks.test_domain_dns_check import run as run_domain_dns
from tests.checks.test_email_check import mail_domain, policy_site, txt
from tests.checks.test_email_check import run as run_email
from tests.checks.test_hsts_preload_check import EXAMPLE as HSTS_UNKNOWN
from tests.checks.test_hsts_preload_check import GITHUB as HSTS_LISTED
from tests.checks.test_hsts_preload_check import answering as hsts_answer
from tests.checks.test_hsts_preload_check import run as run_hsts
from tests.checks.test_http_check import HOST as WEB_HOST
from tests.checks.test_http_check import Site, page, redirect
from tests.checks.test_http_check import run as run_http
from tests.checks.test_ip_check import FakeProvider as FakeLocations
from tests.checks.test_ip_check import Reverse, cloudflare, german, swiss
from tests.checks.test_ip_check import dns_outcome as dns_addresses
from tests.checks.test_ip_check import run as run_ip
from tests.checks.test_ports_check import CLOUDFLARE, IP1, IP2, FakeProvider, facts, found, located
from tests.checks.test_ports_check import dns as ports_dns
from tests.checks.test_ports_check import ip_outcome as ports_ip_outcome
from tests.checks.test_ports_check import run as run_ports
from tests.checks.test_registration_check import Registry
from tests.checks.test_registration_check import run as run_registration
from tests.checks.test_securitytxt_check import GITHUB as SECURITY_TXT
from tests.checks.test_securitytxt_check import WELL_KNOWN, Web
from tests.checks.test_securitytxt_check import run as run_security
from tests.checks.test_securitytxt_check import text as security_text
from tests.checks.test_tls_check import probe_result
from tests.exploit_helpers import FakeExploits, listed, scored
from tests.helpers import create_assessment, create_user, login_as
from tests.test_engine import CONFIG

SCRIPT = "<script>alert(1)</script>"
ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"


# ------------------------------------------------------------------------------ real outcomes


def dns_outcome(host: str = WEB_HOST, txt: str = "v=spf1 -all") -> CheckOutcome:
    cname = "edge.cdn.example.net"
    outcome, _ = run_dns(
        {
            (host, "CNAME"): answer(host, "CNAME", rr(host, 300, "CNAME", f"{cname}.")),
            (host, "A"): answer(
                host, "A", rr(host, 300, "CNAME", f"{cname}."), rr(cname, 60, "A", "93.184.216.34")
            ),
            (host, "AAAA"): answer(host, "AAAA", rr(host, 60, "AAAA", "2606:2800:220:1::1")),
            (host, "MX"): answer(host, "MX", rr(host, 60, "MX", "10 mail.example.com.")),
            (host, "TXT"): answer(host, "TXT", rr(host, 60, "TXT", f'"{txt}"')),
            (host, "CAA"): answer(host, "CAA", rr(host, 60, "CAA", '0 issue "letsencrypt.org"')),
        },
        host=host,
    )
    return outcome


def tls_outcome(**fields: Any) -> CheckOutcome:
    return outcome_from_probe(probe_result(**fields))


def ip_outcome(
    *locations: IpLocation, ptr: dict[str, list[str]] | None = None, aliases: tuple[str, ...] = ()
) -> CheckOutcome:
    """The real IP check run over fake databases."""
    table = {location.ip: location for location in locations}
    return run_ip(FakeLocations(table), dns_addresses(*table, aliases=aliases), Reverse(ptr))


def http_outcome(
    server: str = "nginx", title: str = "Example", location: str | None = None
) -> CheckOutcome:
    site = Site(
        {
            ("https", WEB_HOST, "/"): page(
                headers=[
                    ("Server", server),
                    ("Strict-Transport-Security", "max-age=63072000"),
                    ("Set-Cookie", "sid=SECRET; Secure; HttpOnly; SameSite=Lax"),
                ],
                body=f"<html><head><title>{title}</title></head></html>",
            )
            if location is None
            else redirect(location),
            ("http", WEB_HOST, "/"): redirect(f"https://{WEB_HOST}/"),
        }
    )
    return run_http(site)


def ports_outcome(
    provider: FakeProvider | None = None,
    previous: dict[str, CheckOutcome] | None = None,
    exploits: Any = None,
) -> CheckOutcome:
    """The real ports check over a fake provider (the host name is listed for the address)."""
    provider = provider or FakeProvider(
        {IP1: found(ports=(80, 443), cves=("CVE-2021-23017",), hostnames=(WEB_HOST,))}
    )
    return run_ports(
        provider, previous or {"dns": ports_dns(IP1)}, hostname=WEB_HOST, exploits=exploits
    )


def entry(
    ports: list[int], cves: list[str] | None = None, attribution: str = "ip_only"
) -> dict[str, Any]:
    """One address of a stored ports result, as far as the summary reads it."""
    return {
        "attribution": attribution,
        "facts": {"ports": ports, "vulnerabilities": [{"id": cve} for cve in cves or []]},
    }


# ------------------------------------------------------------------------------ summaries


@pytest.mark.parametrize(
    ("key", "status", "reason", "data", "tone", "text"),
    [
        ("dns", "queued", None, {}, "info", "Queued"),
        ("tls", "running", None, {}, "info", "Running"),
        (
            "dns",
            "ok",
            None,
            {"addresses": ["1.1.1.1", "9.9.9.9"], "blocked": []},
            "ok",
            "2 addresses",
        ),
        ("dns", "ok", None, {"addresses": ["1.1.1.1"], "blocked": []}, "ok", "1 address"),
        (
            "dns",
            "ok",
            None,
            {"addresses": ["1.1.1.1"], "blocked": [{"ip": "10.0.0.1"}]},
            "medium",
            "1 address, 1 private",
        ),
        (
            "dns",
            "ok",
            None,
            {"addresses": [], "blocked": [{"ip": "10.0.0.1"}]},
            "medium",
            "Only private addresses",
        ),
        ("dns", "ok", None, {"dangling_cname": True, "addresses": []}, "high", "Dangling CNAME"),
        ("dns", "ok", None, {"addresses": [], "blocked": []}, "muted", "No address records"),
        ("dns", "no_data", "nxdomain", {}, "muted", "Name does not exist"),
        ("dns", "error", "timeout", {}, "high", "Timed out"),
        (
            "ip",
            "ok",
            None,
            {"addresses": [{"country": "CH", "city": "Bern"}], "countries": ["CH"]},
            "ok",
            "CH · Bern",
        ),
        (
            "ip",
            "ok",
            None,
            {
                "addresses": [{"country": "CH", "city": "Bern"}, {"country": "CH", "city": "Zug"}],
                "countries": ["CH"],
            },
            "ok",
            "CH",
        ),
        (
            "ip",
            "ok",
            None,
            {"addresses": [{"country": "CH"}, {"country": "DE"}], "countries": ["CH", "DE"]},
            "ok",
            "CH, DE",
        ),
        (
            "ip",
            "ok",
            None,
            {"addresses": [{"country": "CH"}], "countries": ["CH"], "edge": True},
            "ok",
            "CH · incl. CDN edge",
        ),
        (
            "ip",
            "ok",
            None,
            {
                "addresses": [{"country": "CA", "network": {"name": "Cloudflare", "edge": True}}],
                "countries": ["CA"],
                "edge": True,
                "all_edge": True,
            },
            "muted",
            "Cloudflare edge",
        ),
        ("ip", "ok", None, {"addresses": [{"asn": 24940}]}, "muted", "Network known, location not"),
        ("ip", "no_data", "not_in_database", {}, "muted", "Not in the location database"),
        ("ip", "unavailable", "datasets_missing", {}, "medium", "Location data not installed"),
        ("ip", "unavailable", "datasets_unreadable", {}, "medium", "Location data unreadable"),
        (
            "ports",
            "ok",
            None,
            {"addresses": [entry([22, 443], ["CVE-2021-23017", "CVE-2019-9511"])]},
            "info",
            "2 ports · 2 CVEs",
        ),
        ("ports", "ok", None, {"addresses": [entry([443])]}, "info", "1 port"),
        ("ports", "ok", None, {"addresses": [entry([])]}, "info", "No open ports seen"),
        (
            "ports",
            "ok",
            None,
            {"addresses": [entry([80, 443], ["CVE-2020-0001"]), entry([80], ["CVE-2020-0001"])]},
            "info",
            "2 ports · 1 CVE",  # the same port and CVE on two addresses count once
        ),
        (
            "ports",
            "ok",
            None,
            {"addresses": [entry([80, 443], ["CVE-2020-0001"], "shared_infrastructure")]},
            "muted",
            "Shared infrastructure",  # a CDN's ports and CVEs are not the host's
        ),
        (
            "ports",
            "ok",
            None,
            {"addresses": [entry([443]), entry([80], ["CVE-1"], "shared_infrastructure")]},
            "info",
            "1 port · plus shared",
        ),
        (
            "ports",
            "ok",
            None,
            {"addresses": [entry([443])], "complete": False},
            "medium",
            "1 port · incomplete",
        ),
        ("ports", "ok", None, {"addresses": [{"facts": None}]}, "muted", "No data"),
        (
            "ports",
            "no_data",
            "no_information",
            {},
            "muted",
            "The provider knows nothing about this address",
        ),
        ("ports", "unavailable", "disabled", {}, "medium", "Switched off"),
        ("ports", "unavailable", "missing_api_key", {}, "medium", "No API key configured"),
        ("ports", "unavailable", "invalid_key", {}, "medium", "API key rejected"),
        ("ports", "unavailable", "membership_required", {}, "medium", "Needs a paid Shodan plan"),
        ("ports", "unavailable", "rate_limited", {}, "medium", "Rate limited"),
        ("ports", "error", "http_503", {}, "high", "HTTP error 503"),
        ("ports", "error", "timeout", {}, "high", "Timed out"),
        ("ports", "skipped", "needs:dns", {}, "muted", "Skipped: dns did not succeed"),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "fail", "problems": []},
                "dmarc": {"found": True, "policy": "reject"},
                "errors": {},
            },
            "ok",
            "SPF -all · DMARC reject",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "softfail", "problems": []},
                "dmarc": {"found": True, "policy": "quarantine"},
            },
            "ok",
            "SPF ~all · DMARC quarantine",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "fail", "problems": []},
                "dmarc": {"found": True, "policy": "none"},
            },
            "medium",
            "SPF -all · DMARC none",
        ),
        (
            "email",
            "ok",
            None,
            {"mx": {"found": True}, "spf": {"found": False}, "dmarc": {"found": False}},
            "medium",
            "No SPF · No DMARC",
        ),
        (
            "email",
            "ok",
            None,
            {"mx": {"found": False}, "spf": {"found": False}, "dmarc": {"found": False}},
            "muted",  # a domain without mail matters less
            "No SPF · No DMARC",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "pass", "problems": []},
                "dmarc": {"found": True, "policy": "reject"},
            },
            "high",  # +all: anyone may send as this domain
            "SPF +all · DMARC reject",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": None, "problems": ["no_all"]},
                "dmarc": {"found": True, "policy": None, "problems": ["invalid_policy"]},
            },
            "medium",
            "SPF without all · DMARC invalid",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "fail", "problems": ["multiple_records"]},
                "dmarc": {"found": True, "policy": "reject"},
            },
            "medium",  # two SPF records: receivers treat that as an error
            "SPF -all · DMARC reject",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": "fail", "problems": []},
                "dmarc": {"found": None, "error": "timeout"},
                "errors": {"dmarc": "timeout"},
            },
            "medium",
            "SPF -all · DMARC unknown · incomplete",
        ),
        (
            "email",
            "ok",
            None,
            {
                "mx": {"found": True},
                "spf": {"found": True, "qualifier": None, "redirect": "spf.example.net"},
                "dmarc": {"found": True, "policy": "reject"},
            },
            "medium",  # a redirect that could not be read: not known to be strict
            "SPF redirect · DMARC reject",
        ),
        (
            "registration",
            "ok",
            None,
            {"days_to_expiry": 312, "registrar": {"name": "MarkMonitor Inc."}},
            "ok",
            "Expires in 312 days · MarkMonitor Inc.",
        ),
        ("registration", "ok", None, {"days_to_expiry": 31}, "ok", "Expires in 31 days"),
        ("registration", "ok", None, {"days_to_expiry": 30}, "medium", "Expires in 30 days"),
        ("registration", "ok", None, {"days_to_expiry": 1}, "medium", "Expires in 1 day"),
        ("registration", "ok", None, {"days_to_expiry": 0}, "medium", "Expires in 0 days"),
        ("registration", "ok", None, {"days_to_expiry": -1}, "high", "Expired 1 day ago"),
        ("registration", "ok", None, {"days_to_expiry": -40}, "high", "Expired 40 days ago"),
        (
            "registration",
            "ok",
            None,
            {"days_to_expiry": None, "registrar": {"name": "cyon AG"}},
            "muted",
            "No dates published · cyon AG",
        ),
        (
            "registration",
            "ok",
            None,
            {"days_to_expiry": None, "registrar": None},
            "muted",
            "No dates published",
        ),
        (
            "registration",
            "no_data",
            "no_rdap_service",
            {},
            "muted",
            "The registry offers no RDAP service",
        ),
        ("registration", "no_data", "not_found", {}, "muted", "The registry has no such domain"),
        ("registration", "unavailable", "disabled", {}, "medium", "Switched off"),
        ("registration", "unavailable", "rate_limited", {}, "medium", "Rate limited"),
        (
            "registration",
            "error",
            "bootstrap_failed",
            {},
            "high",
            "IANA's list of RDAP servers could not be read",
        ),
        (
            "security_txt",
            "ok",
            None,
            {"problems": [], "days_to_expiry": 200},
            "ok",
            "Expires in 200 days",
        ),
        (
            "security_txt",
            "ok",
            None,
            {"problems": [], "days_to_expiry": 1},
            "ok",
            "Expires in 1 day",
        ),
        ("security_txt", "ok", None, {"problems": [], "days_to_expiry": None}, "ok", "Present"),
        (
            "security_txt",
            "ok",
            None,
            {"problems": ["missing_contact"], "days_to_expiry": 100},
            "medium",
            "Expires in 100 days · 1 problem",
        ),
        (
            "security_txt",
            "ok",
            None,
            {"problems": ["offsite", "not_https"], "days_to_expiry": 5},
            "medium",
            "Expires in 5 days · 2 problems",
        ),
        (
            "security_txt",
            "ok",
            None,
            {"problems": ["expired"], "days_to_expiry": -3},
            "high",
            "Expired",
        ),
        (
            "security_txt",
            "ok",
            None,
            {"problems": ["expired", "offsite"], "days_to_expiry": -3},
            "high",
            "Expired",
        ),
        ("security_txt", "no_data", "no_security_txt", {}, "muted", "No security.txt found"),
        ("security_txt", "error", "timeout", {}, "high", "Timed out"),
        ("hsts_preload", "ok", None, {"status": "preloaded"}, "ok", "Preloaded"),
        ("hsts_preload", "ok", None, {"status": "pending"}, "info", "Pending"),
        ("hsts_preload", "ok", None, {"status": "rejected"}, "medium", "Rejected"),
        ("hsts_preload", "ok", None, {"status": "removed"}, "medium", "Removed"),
        ("hsts_preload", "ok", None, {"status": "unknown"}, "muted", "Not on the list"),
        ("hsts_preload", "ok", None, {"status": "something-new"}, "muted", "Unknown"),
        ("hsts_preload", "unavailable", "disabled", {}, "medium", "Switched off"),
        ("hsts_preload", "error", "http_500", {}, "high", "HTTP error 500"),
        (
            "breaches",
            "ok",
            None,
            {"total": 1, "latest_breach_date": "2013-10-04"},
            "medium",
            "1 public breach · 2013-10",
        ),
        (
            "breaches",
            "ok",
            None,
            {"total": 3, "latest_breach_date": None},
            "medium",
            "3 public breaches",
        ),
        (
            "breaches",
            "no_data",
            "no_breach_known",
            {},
            "muted",
            "No public breach known to Have I Been Pwned",
        ),
        ("breaches", "unavailable", "rate_limited", {}, "medium", "Rate limited"),
        (
            "domain_dns",
            "ok",
            None,
            {
                "ns": {"found": True, "count": 4, "operators": ["a", "b"], "problems": []},
                "caa": {"found": True},
            },
            "ok",
            "4 name servers · 2 operators · CAA",
        ),
        (
            "domain_dns",
            "ok",
            None,
            {
                "ns": {"found": True, "count": 2, "operators": ["a"], "problems": []},
                "caa": {"found": False},
            },
            "muted",
            "2 name servers · 1 operator · no CAA",
        ),
        (
            "domain_dns",
            "ok",
            None,
            {
                "ns": {
                    "found": True,
                    "count": 2,
                    "operators": ["a", "b"],
                    "problems": ["single_network"],
                },
                "caa": {"found": True},
            },
            "medium",
            "2 name servers · 2 operators · CAA",
        ),
        (
            "domain_dns",
            "ok",
            None,
            {"ns": {"found": False}, "caa": {"found": True}},
            "medium",
            "No name servers found · CAA",
        ),
        (
            "domain_dns",
            "ok",
            None,
            {"ns": {"found": None, "error": "timeout"}, "caa": {"found": None, "error": "timeout"}},
            "muted",
            "Name servers unknown · CAA unknown",
        ),
        ("email", "no_data", "nxdomain", {}, "muted", "Name does not exist"),
        ("email", "error", "timeout", {}, "high", "Timed out"),
        (
            "tls",
            "ok",
            None,
            {"verified": True, "certificate": {"days_remaining": 45}},
            "ok",
            "Valid · 45 days left",
        ),
        (
            "tls",
            "ok",
            None,
            {"verified": True, "certificate": {"days_remaining": 1}},
            "medium",
            "Expires in 1 day",
        ),
        (
            "tls",
            "ok",
            None,
            {"verified": True, "certificate": {"days_remaining": 12}},
            "medium",
            "Expires in 12 days",
        ),
        ("tls", "ok", None, {"verified": False, "failures": ["expired"]}, "high", "Expired"),
        (
            "tls",
            "ok",
            None,
            {"verified": False, "failures": ["hostname_mismatch", "expired"]},
            "high",
            "Name mismatch",
        ),
        ("tls", "no_data", "refused", {}, "muted", "Connection refused"),
        ("tls", "error", "untrusted", {}, "high", "Not trusted"),  # no certificate could be read
        ("tls", "error", "handshake_failed", {}, "high", "TLS handshake failed"),
        ("tls", "skipped", "needs:dns", {}, "muted", "Skipped: dns did not succeed"),
        ("tls", "skipped", "no_public_address", {}, "muted", "No public address to connect to"),
        ("http", "ok", None, {"status": 200}, "ok", "200"),
        ("http", "ok", None, {"status": 404}, "medium", "404"),
        ("http", "ok", None, {"status": 503}, "high", "503"),
        ("http", "ok", None, {"status": 200, "scheme": "http"}, "medium", "200 · HTTP only"),
        (
            "http",
            "ok",
            None,
            {"status": 301, "redirect_incomplete": {"reason": "x"}},
            "medium",
            "301 · redirect not followed",
        ),
        ("http", "no_data", "no_web_server", {}, "muted", "No web server"),
        ("http", "error", "something_new", {}, "high", "something_new"),
        ("http", "unavailable", None, {}, "medium", "Unavailable"),
        ("future_check", "ok", None, {}, "ok", "Done"),
    ],
)
def test_summaries_say_what_was_collected(
    key: str, status: str, reason: str | None, data: dict[str, Any], tone: str, text: str
) -> None:
    cell = host_view.summarize(key, status, reason, data)
    assert (cell.tone, cell.text) == (tone, text)


def test_the_summaries_understand_what_the_real_checks_produce() -> None:
    """The contract between the checks' data and the display: real outputs, not hand-made ones."""
    assert host_view.summarize("dns", *_parts(dns_outcome())).text == "2 addresses"
    assert host_view.summarize("ip", *_parts(ip_outcome(swiss()))).text == "CH · Bern"
    both = ip_outcome(swiss(), german())
    assert host_view.summarize("ip", *_parts(both)).text == "CH, DE"
    assert host_view.summarize("ip", *_parts(ip_outcome(cloudflare()))).text == "Cloudflare edge"
    assert host_view.summarize("tls", *_parts(tls_outcome())).text == "Valid · 60 days left"
    bad = tls_outcome(
        is_valid=False, chain_trust=False, failure_reasons=["CERTIFICATE_EXPIRED"], forensic=True
    )
    assert host_view.summarize("tls", *_parts(bad)).text == "Expired"
    assert host_view.summarize("http", *_parts(http_outcome())).text == "200"


def test_the_ports_summary_understands_what_the_real_check_produces() -> None:
    own = run_ports(
        FakeProvider({IP1: found(ports=(22, 443), cves=("CVE-2021-23017",))}),
        {"dns": ports_dns(IP1)},
    )
    assert host_view.summarize("ports", *_parts(own)).text == "2 ports · 1 CVE"

    behind_cdn = {"dns": ports_dns(IP1), "ip": ports_ip_outcome(located(IP1, CLOUDFLARE, 13335))}
    shared = ports_outcome(FakeProvider({IP1: found(cves=("CVE-2020-0001",))}), behind_cdn)
    assert host_view.summarize("ports", *_parts(shared)).text == "Shared infrastructure"

    unknown = run_ports(FakeProvider(), {"dns": ports_dns(IP1)})
    text = host_view.summarize("ports", *_parts(unknown)).text
    assert text == "The provider knows nothing about this address"

    partial = run_ports(
        FakeProvider({IP1: found(ports=(443,)), IP2: PortsLookup("error", "http_500")}),
        {"dns": ports_dns(IP1, IP2)},
    )
    assert host_view.summarize("ports", *_parts(partial)).text == "1 port · incomplete"


def test_the_email_summary_understands_what_the_real_check_produces() -> None:
    outcome, _ = run_email(mail_domain(), policy_site)
    assert host_view.summarize("email", *_parts(outcome)).text == "SPF -all · DMARC reject"
    assert host_view.summarize("email", *_parts(outcome)).tone == "ok"

    script = mail_domain()
    del script[("_dmarc.example.com", "TXT")]
    weak, _ = run_email(script, policy_site)
    cell = host_view.summarize("email", *_parts(weak))
    assert (cell.tone, cell.text) == ("medium", "SPF -all · No DMARC")

    bare, _ = run_email({})
    cell = host_view.summarize("email", *_parts(bare))
    assert (cell.tone, cell.text) == ("muted", "No SPF · No DMARC")


def test_the_registration_summary_understands_what_the_real_check_produces() -> None:
    cell = host_view.summarize("registration", *_parts(run_registration("example.com", Registry())))
    assert cell.tone == "ok" and cell.text.startswith("Expires in ")
    assert cell.text.endswith("RESERVED-Internet Assigned Numbers Authority")
    swiss = host_view.summarize("registration", *_parts(run_registration("admin.ch", Registry())))
    assert (swiss.tone, swiss.text) == ("muted", "No dates published · cyon AG")


def test_the_new_domain_summaries_understand_what_the_real_checks_produce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.checks.breaches.LIMITERS", FakeLimiters())
    # GitHub's own file, served from github.com: nothing is wrong with it
    served = Web({("github.com", WELL_KNOWN): security_text(SECURITY_TXT)})
    security = run_security(served, "github.com")
    cell = host_view.summarize("security_txt", *_parts(security))
    assert cell.tone == "ok" and cell.text.startswith("Expires in ")
    assert host_view.summarize("security_txt", *_parts(run_security(Web()))).text == (
        "No security.txt found"
    )

    listed = host_view.summarize("hsts_preload", *_parts(run_hsts(hsts_answer(HSTS_LISTED))))
    unlisted = host_view.summarize("hsts_preload", *_parts(run_hsts(hsts_answer(HSTS_UNKNOWN))))
    assert (listed.text, unlisted.text) == ("Preloaded", "Not on the list")

    breached = run_breaches(breaches_answer(ADOBE))
    assert host_view.summarize("breaches", *_parts(breached)).text == "1 public breach · 2013-10"
    several = run_breaches(breaches_answer(LINKEDIN), "linkedin.com")
    assert host_view.summarize("breaches", *_parts(several)).text == "3 public breaches · 2023-11"
    none = run_breaches(breaches_answer([]))
    assert host_view.summarize("breaches", *_parts(none)).tone == "muted"

    setup = host_view.summarize("domain_dns", *_parts(run_domain_dns(dns_setup())[0]))
    assert (setup.tone, setup.text) == ("ok", "4 name servers · 2 operators · CAA")


def _parts(outcome: CheckOutcome) -> tuple[str, str | None, dict[str, Any]]:
    return outcome.status, outcome.reason_code, outcome.data


def test_raw_json_is_bounded() -> None:
    text, cut = host_view.raw_json({"x": "y" * 10})
    assert cut is False and '"x": "yyyyyyyyyy"' in text
    big, cut = host_view.raw_json({"x": "y" * (host_view.MAX_RAW_JSON_CHARS + 5)})
    assert cut is True and len(big) == host_view.MAX_RAW_JSON_CHARS


# ------------------------------------------------------------------------------ pages


@pytest.fixture
def signed_in(client: FlaskClient, db_session: Session) -> tuple[FlaskClient, Assessment, Scan]:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "example.com")
    login_as(client, user)
    scan = scan_service.start_scan(db_session, assessment, user, CONFIG)
    scan.status = "completed"  # finished: the panel does not poll
    scan.finished_at = utc_now()
    db_session.commit()
    return client, assessment, scan


def add_host(
    session: Session,
    scan: Scan,
    hostname: str,
    results: dict[str, tuple[CheckOutcome, str | None]] | dict[str, CheckOutcome],
) -> Host:
    host = Host(scan_id=scan.id, hostname=hostname, source="ct", ct_sources=["ctlogs"])
    session.add(host)
    session.flush()
    for key, item in results.items():
        outcome, status = item if isinstance(item, tuple) else (item, None)
        session.add(
            CheckResult(
                scan_id=scan.id,
                host_id=host.id,
                check_key=key,
                status=status or outcome.status,
                reason_code=outcome.reason_code,
                data=outcome.data,
                source=outcome.source,
                collected_at=utc_now(),
                duration_ms=12,
            )
        )
    session.commit()
    return host


def healthy() -> dict[str, CheckOutcome]:
    return {
        "dns": dns_outcome(),
        "ip": ip_outcome(swiss()),
        "ports": ports_outcome(),
        "tls": tls_outcome(),
        "http": http_outcome(),
    }


def test_the_hosts_table_has_one_cell_per_check_and_links_to_the_host(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    host = add_host(db_session, scan, WEB_HOST, healthy())

    body = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "2 addresses" in body and "Valid · 60 days left" in body
    assert "Location" in body and "CH · Bern" in body
    assert "Ports" in body and "2 ports · 1 CVE" in body
    assert re.search(r">\s*200\s*</span>", body)
    assert f"/assessments/{assessment.id}/hosts/{host.id}" in body


def host_page(client: Any, assessment: Assessment, host: Host) -> str:
    response = client.get(f"/assessments/{assessment.id}/hosts/{host.id}")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_the_ports_panel_shows_what_is_known_about_the_exploitation_of_each_cve(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    lookup = FakeExploits(
        {
            "CVE-2021-23017": exploit_data.Enrichment(
                listed("CVE-2021-23017", ransomware=True), scored(0.97312)
            )
        }
    )
    host = add_host(
        db_session, scan, WEB_HOST, {**healthy(), "ports": ports_outcome(exploits=lookup)}
    )
    body = host_page(client, assessment, host)
    assert "known exploited (CISA KEV)" in body and "used in ransomware" in body
    assert "EPSS 97.3 %" in body
    assert "CISA KEV, as of 2026-10-04" in body and "EPSS, as of 2026-10-06" in body
    assert "Not ranked" not in body and "out of date" not in body
    # both lists are credited, with a link to where they come from
    assert "CVEs ranked with" in body and "nothing about this assessment was sent" in body
    assert 'href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"' in body
    assert 'href="https://www.first.org/epss/"' in body and "FIRST.Org, Inc." in body


def test_the_ports_panel_never_shows_an_epss_score_as_a_certainty(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    lookup = FakeExploits({"CVE-2021-23017": exploit_data.Enrichment(None, scored(0.99999, 1.0))})
    host = add_host(
        db_session, scan, WEB_HOST, {**healthy(), "ports": ports_outcome(exploits=lookup)}
    )
    body = host_page(client, assessment, host)
    assert "EPSS &gt; 99.9 %" in body and "100.0" not in body


def test_the_ports_panel_says_when_the_cves_are_not_ranked(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    lookup = FakeExploits(snapshot=exploit_data.Snapshot())
    host = add_host(
        db_session, scan, WEB_HOST, {**healthy(), "ports": ports_outcome(exploits=lookup)}
    )
    body = host_page(client, assessment, host)
    assert "Not ranked: the exploitation data (CISA KEV, EPSS) is not installed." in body
    assert "flask datasets update" in body and "known exploited" not in body
    assert "CVEs ranked with" not in body and "first.org/epss" not in body  # nothing to credit


def test_the_ports_panel_says_when_the_exploitation_data_is_out_of_date(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    stale = exploit_data.Snapshot("2026-09-01", "2026-09-01", stale=True)
    host = add_host(
        db_session,
        scan,
        WEB_HOST,
        {**healthy(), "ports": ports_outcome(exploits=FakeExploits(snapshot=stale))},
    )
    assert "This data is out of date" in host_page(client, assessment, host)


def test_a_ports_result_from_before_exploitation_data_still_shows(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    outcome = ports_outcome()  # the plain check: no exploitation data configured
    for entry in outcome.data["addresses"]:
        entry["facts"].pop("exploit_data", None)
        for vulnerability in entry["facts"]["vulnerabilities"]:
            vulnerability.pop("kev", None)
            vulnerability.pop("epss", None)
    outcome.data.pop("exploit_data", None)
    host = add_host(db_session, scan, WEB_HOST, {**healthy(), "ports": outcome})
    body = host_page(client, assessment, host)
    assert "1 CVE reported" in body and "Not ranked" in body  # an old result is not "ranked"


def test_a_host_still_being_checked_shows_queued_cells(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    queued = CheckOutcome("ok")
    add_host(
        db_session,
        scan,
        "new.example.com",
        {key: (queued, "queued") for key in ("dns", "ip", "ports", "tls", "http")},
    )
    body = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert body.count("Queued") >= 5


def test_the_host_page_shows_the_facts_of_every_check(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    host = add_host(db_session, scan, WEB_HOST, healthy())

    response = client.get(f"/assessments/{assessment.id}/hosts/{host.id}")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    # order and headings
    sections = (
        "DNS",
        "IP addresses and location",
        "Open ports and CVEs",
        "TLS certificate",
        "HTTP",
    )
    keys = ("dns", "ip", "ports", "tls", "http")
    positions = [body.index(f'id="check-{key}"') for key in keys]
    assert positions == sorted(positions) and all(title in body for title in sections)
    # IP location
    for fact in ("85.1.1.1", "Switzerland", "Bern", "AS3303", "Swisscom", "46.85, 7.68"):
        assert fact in body
    assert "IP geolocation by DB-IP.com" in body
    # ports and CVEs
    assert "A snapshot, not a port scan" in body and "Data by Shodan." in body
    assert "Host name listed" in body and "1 CVE reported" in body
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2021-23017"' in body
    assert 'rel="noopener noreferrer"' in body
    # DNS
    for fact in ("93.184.216.34", "2606:2800:220:1::1", "edge.cdn.example.net", "letsencrypt.org"):
        assert fact in body
    assert "v=spf1 -all" in body and "10 mail.example.com" in body
    # TLS
    for fact in (
        "Verified",
        "www.example.com",
        "Example CA",
        "secp256r1",
        "ecdsa-with-SHA256",
        "TLSv1.3",
    ):
        assert fact in body
    assert "CN=Example Root" in body and "SHA-256 fingerprint" in body
    # HTTP
    for fact in (
        "nginx",
        "max-age=63072000",
        "Redirects to HTTPS",
        "sid",
        "Cookie values are never stored",
    ):
        assert fact in body
    assert "Not present" in body  # the absent security headers are explicit
    assert "SECRET" not in body  # a cookie value never reaches the page
    # raw JSON for each check, collapsed
    assert body.count("Raw data (JSON)") == 5 and "<details" in body


def test_a_bad_certificate_is_labelled_and_its_forensic_origin_explained(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    bad = tls_outcome(
        is_valid=False,
        chain_trust=False,
        failure_reasons=["CERTIFICATE_EXPIRED"],
        days_until_expiration=-12,
        forensic=True,
    )
    host = add_host(db_session, scan, WEB_HOST, {"tls": bad})
    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Not verified" in body and "Expired" in body
    assert "Certificate read without trust" in body
    assert "expired 12 days ago" in body


def test_a_failed_check_shows_its_reason_instead_of_facts(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    host = add_host(
        db_session,
        scan,
        WEB_HOST,
        {
            "dns": dns_outcome(),
            "tls": CheckOutcome(
                "error", "timeout", {"ip": "93.184.216.34", "failures": ["timeout"]}
            ),
            "http": CheckOutcome("skipped", "needs:dns"),
        },
    )
    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Timed out" in body and "Skipped: dns did not succeed" in body
    assert "SHA-256 fingerprint" not in body


def test_everything_the_target_supplies_is_escaped(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    results = {
        "dns": dns_outcome(txt=SCRIPT),
        "tls": tls_outcome(
            subject_cn=SCRIPT, sans=[SCRIPT], chain_subjects=[SCRIPT], issuer_cn=SCRIPT
        ),
        "http": http_outcome(server=SCRIPT, title=ESCAPED),  # the title arrives HTML-encoded
    }
    host = add_host(db_session, scan, WEB_HOST, results)

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert SCRIPT not in body  # nowhere, not even in the raw JSON
    assert body.count(ESCAPED) >= 6
    table = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert SCRIPT not in table


def test_a_redirect_target_with_markup_is_escaped_too(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    host = add_host(
        db_session,
        scan,
        WEB_HOST,
        {"http": http_outcome(location=f"https://{WEB_HOST}/{SCRIPT}")},
    )
    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert SCRIPT not in body and "Redirects" in body


def test_the_host_page_is_as_private_as_its_assessment(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    mine = create_assessment(db_session, owner, "mine.example", "private")
    scan = scan_service.start_scan(db_session, mine, owner, CONFIG)
    scan.status = "completed"
    db_session.commit()
    host = add_host(db_session, scan, "www.mine.example", healthy())

    other = create_user(db_session)
    theirs = create_assessment(db_session, other, "theirs.example", "private")
    login_as(client, other)
    assert client.get(f"/assessments/{mine.id}/hosts/{host.id}").status_code == 404
    # A host that exists, asked for under an assessment the user does own: still not found.
    assert client.get(f"/assessments/{theirs.id}/hosts/{host.id}").status_code == 404
    login_as(client, owner)
    assert client.get(f"/assessments/{mine.id}/hosts/{host.id}").status_code == 200
    assert client.get(f"/assessments/{mine.id}/hosts/{uuid.uuid4()}").status_code == 404


def test_a_cdn_address_is_not_presented_as_the_hosts_own_servers(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    behind_cdn = {"dns": ports_dns(IP1), "ip": ports_ip_outcome(located(IP1, CLOUDFLARE, 13335))}
    outcome = ports_outcome(
        FakeProvider({IP1: found(ports=(80, 443, 8080), cves=("CVE-2020-0001",))}), behind_cdn
    )
    host = add_host(db_session, scan, WEB_HOST, {"ports": outcome})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Shared infrastructure" in body
    assert "belongs to a CDN or other shared network" in body and "network: Cloudflare" in body
    table = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Shared infrastructure" in table and "1 CVE" not in table


def test_the_keyless_provider_is_labelled_with_its_licence_note(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    provider = FakeProvider({IP1: PortsLookup("ok", facts=facts(provider="internetdb"))})
    provider.name = "internetdb"
    host = add_host(db_session, scan, WEB_HOST, {"ports": ports_outcome(provider)})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Shodan InternetDB" in body and "free for non-commercial use only" in body


def test_an_address_the_provider_does_not_know_says_so_instead_of_looking_clean(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    host = add_host(db_session, scan, WEB_HOST, {"ports": ports_outcome(FakeProvider())})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "The provider knows nothing about this address" in body
    assert "No open ports were seen" not in body  # unknown is not the same as none
    assert "Raw data (JSON)" in body


def test_an_unconfigured_ports_check_explains_how_to_fix_it(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    unconfigured = CheckOutcome("unavailable", "missing_api_key", {"addresses_total": 1})
    host = add_host(db_session, scan, WEB_HOST, {"ports": unconfigured})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "No API key configured" in body and "SHODAN_API_KEY" in body
    table = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "No API key configured" in table


def test_a_partly_failed_ports_check_shows_which_address_failed(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    provider = FakeProvider({IP1: found(), IP2: PortsLookup("error", "http_503")})
    outcome = ports_outcome(provider, {"dns": ports_dns(IP1, IP2)})
    host = add_host(db_session, scan, WEB_HOST, {"ports": outcome})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Some addresses could not be checked" in body
    assert IP2 in body and "HTTP error 503" in body


def test_hostile_text_from_the_ports_provider_is_escaped(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    hostile = PortFacts(
        ip=IP1,
        provider="shodan",
        services=(PortService(443, "tcp", SCRIPT, SCRIPT, (SCRIPT,)),),
        vulnerabilities=(Vulnerability(f'CVE-2021-1"{SCRIPT}', 9.8, SCRIPT, True),),
        hostnames=(SCRIPT,),
        tags=(SCRIPT,),
        cpes=(SCRIPT,),
        org=SCRIPT,
        asn=SCRIPT,
    )
    outcome = ports_outcome(FakeProvider({IP1: PortsLookup("ok", facts=hostile)}))
    host = add_host(db_session, scan, WEB_HOST, {"ports": outcome})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert SCRIPT not in body and body.count(ESCAPED) >= 6
    table = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert SCRIPT not in table


# ------------------------------------------------------------------------------ the filter


def seed_states(session: Session, scan: Scan) -> None:
    add_host(session, scan, "good.example.com", healthy())
    add_host(
        session,
        scan,
        "broken.example.com",
        {"dns": CheckOutcome("error", "timeout"), "tls": CheckOutcome("skipped", "needs:dns")},
    )
    add_host(
        session,
        scan,
        "busy.example.com",
        {"dns": (CheckOutcome("ok"), "running"), "tls": (CheckOutcome("ok"), "queued")},
    )


@pytest.mark.parametrize(
    ("state", "shown", "hidden"),
    [
        ("all", {"good", "broken", "busy"}, set()),
        ("", {"good", "broken", "busy"}, set()),
        ("nonsense", {"good", "broken", "busy"}, set()),  # unknown values mean "all"
        ("problems", {"broken"}, {"good", "busy"}),
        ("pending", {"busy"}, {"good", "broken"}),
    ],
)
def test_the_state_filter_narrows_the_hosts(
    signed_in: Any, db_session: Session, state: str, shown: set[str], hidden: set[str]
) -> None:
    client, assessment, scan = signed_in
    seed_states(db_session, scan)
    body = client.get(f"/assessments/{assessment.id}?state={state}").get_data(as_text=True)
    for name in shown:
        assert f"{name}.example.com" in body
    for name in hidden:
        assert f"{name}.example.com" not in body


def test_the_filters_combine_and_the_polling_url_keeps_them(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    seed_states(db_session, scan)
    body = client.get(f"/assessments/{assessment.id}?state=problems&q=zzz").get_data(as_text=True)
    assert "No host matches this filter." in body

    scan.status = "running"  # an active scan polls its panel; the filter must survive the swaps
    db_session.commit()
    panel = client.get(f"/assessments/{assessment.id}/scan-panel?state=problems&q=bro").get_data(
        as_text=True
    )
    assert "state=problems" in panel and "q=bro" in panel and "every 2s" in panel
    assert 'hx-preserve="true"' in panel  # what is typed in the filter survives a swap


# ------------------------------------------------------------------------------ details


def test_sections_come_in_a_fixed_order_with_unknown_checks_last(
    signed_in: Any, db_session: Session
) -> None:
    _, _, scan = signed_in
    host = add_host(
        db_session,
        scan,
        WEB_HOST,
        {"zzz_future": CheckOutcome("ok"), "http": CheckOutcome("ok"), "dns": CheckOutcome("ok")},
    )
    detail = host_view.get_host_detail(db_session, host.id)
    assert detail is not None
    assert [section.key for section in detail.sections] == ["dns", "http", "zzz_future"]
    assert detail.sections[-1].title == "zzz_future"  # unknown checks keep their key as title


def test_an_unknown_host_has_no_detail(db_session: Session) -> None:
    assert host_view.get_host_detail(db_session, uuid.uuid4()) is None


# ------------------------------------------------------------------------------ IP location


def test_a_cdn_address_is_explained_not_presented_as_a_data_centre(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    host = add_host(db_session, scan, WEB_HOST, {"ip": ip_outcome(cloudflare())})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "CDN or anycast network" in body and "not where data is processed or stored" in body
    assert "Cloudflare · edge" in body and "AS13335" in body
    table = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Cloudflare edge" in table  # the table shows the network, not "Toronto"
    assert "Toronto" not in table


def test_missing_location_data_is_explained_on_the_host_page_and_the_scan_panel(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    unavailable = CheckOutcome("unavailable", "datasets_missing", {"addresses": ["85.1.1.1"]})
    host = add_host(db_session, scan, WEB_HOST, {"ip": unavailable})

    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert "Location data not installed" in body and "flask datasets update" in body
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "IP location data is not installed" in panel


def test_the_scan_panel_is_quiet_when_the_location_data_is_there(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_host(db_session, scan, WEB_HOST, healthy())
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "IP location data is not installed" not in panel


def test_hostile_text_in_reverse_dns_and_the_databases_is_escaped(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    hostile = IpLocation("85.1.1.1", "CH", SCRIPT, "EU", SCRIPT, SCRIPT, None, None, 3303, SCRIPT)
    host = add_host(
        db_session, scan, WEB_HOST, {"ip": ip_outcome(hostile, ptr={"85.1.1.1": [SCRIPT]})}
    )
    body = client.get(f"/assessments/{assessment.id}/hosts/{host.id}").get_data(as_text=True)
    assert SCRIPT not in body and body.count(ESCAPED) >= 4


def test_the_db_ip_attribution_is_on_every_page_of_the_app(signed_in: Any) -> None:
    client, assessment, _ = signed_in
    for path in ("/assessments/", f"/assessments/{assessment.id}"):
        body = client.get(path).get_data(as_text=True)
        assert 'href="https://db-ip.com"' in body and "IP geolocation by DB-IP.com" in body
        assert "CC BY 4.0" in body


# ------------------------------------------------------------------------------ domain checks


def add_domain_result(
    session: Session, scan: Scan, key: str, outcome: CheckOutcome, status: str | None = None
) -> None:
    session.add(
        CheckResult(
            scan_id=scan.id,
            host_id=None,
            check_key=key,
            status=status or outcome.status,
            reason_code=outcome.reason_code,
            data=outcome.data,
            source=outcome.source,
            collected_at=utc_now(),
            duration_ms=40,
        )
    )
    session.commit()


def email_outcome(script: dict[tuple[str, str], Any] | None = None) -> CheckOutcome:
    outcome, _ = run_email(mail_domain() if script is None else script, policy_site)
    return outcome


def test_the_assessment_page_lists_the_domain_checks_with_a_link_to_the_details(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "email", email_outcome())

    body = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Domain checks" in body and "Email security" in body
    assert "SPF -all · DMARC reject" in body
    assert f"/assessments/{assessment.id}/domain#check-email" in body


def test_the_domain_page_shows_every_part_of_the_email_check(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "email", email_outcome())

    response = client.get(f"/assessments/{assessment.id}/domain")
    body = response.get_data(as_text=True)
    assert response.status_code == 200 and 'id="check-email"' in body
    # MX and who handles the mail
    assert "aspmx.l.google.com" in body and "Google Workspace" in body
    # SPF
    assert "v=spf1 include:_spf.google.com -all" in body and "Hard fail (-all)" in body
    assert "2 of 10 allowed" in body
    # DMARC
    assert "dmarc@example.com" in body and "Aggregate reports" in body
    # DKIM
    assert "google" in body and "2048 bits" in body and "Selectors cannot be listed" in body
    # MTA-STS, TLS-RPT, BIMI
    assert "enforce" in body and "20260901T000000" in body
    assert "tls@example.com" in body and "https://example.com/logo.svg" in body
    assert body.count("Raw data (JSON)") == 1


def test_what_is_absent_and_what_could_not_be_asked_look_different(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    script = mail_domain()
    del script[("_smtp._tls.example.com", "TXT")]  # absent
    script[("_dmarc.example.com", "TXT")] = dns_timeout()  # could not be asked
    add_domain_result(db_session, scan, "email", email_outcome(script))

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "Not found" in body  # TLS-RPT
    assert "Could not be checked" in body and "Timed out" in body  # DMARC


def dns_timeout() -> Any:
    from tests.checks.test_dns_check import TIMEOUT

    return TIMEOUT


def test_a_redirecting_spf_and_revoked_selectors_are_explained(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    script = mail_domain()
    script[("example.com", "TXT")] = txt("example.com", "v=spf1 redirect=spf.example.net")
    script[("spf.example.net", "TXT")] = txt("spf.example.net", "v=spf1 ip4:192.0.2.1 -all")
    script[("k1._domainkey.example.com", "TXT")] = txt("k1._domainkey.example.com", "v=DKIM1; p=")
    add_domain_result(db_session, scan, "email", email_outcome(script))

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "decided by the redirect to spf.example.net" in body and "Hard fail (-all)" in body
    assert "Revoked selectors (empty key): k1" in body
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "SPF -all · DMARC reject" in panel


def test_a_short_dkim_key_and_a_weak_spf_are_visible(signed_in: Any, db_session: Session) -> None:
    from tests.checks.test_email_check import RSA_1024, public_key_record

    client, assessment, scan = signed_in
    script = mail_domain()
    script[("google._domainkey.example.com", "TXT")] = txt(
        "google._domainkey.example.com", f"v=DKIM1; k=rsa; p={public_key_record(RSA_1024)}"
    )
    script[("example.com", "TXT")] = txt("example.com", "v=spf1 +all", "v=spf1 -all")
    add_domain_result(db_session, scan, "email", email_outcome(script))

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "1024 bits" in body and "short" in body
    assert "Allows everyone (+all)" in body
    assert "More than one record" in body  # the problem is spelled out, not just coded


def test_a_domain_without_a_scan_or_results_says_so(
    client: FlaskClient, db_session: Session
) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "quiet.example")
    login_as(client, user)
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "No scan has run yet" in body

    scan_service.start_scan(db_session, assessment, user, CONFIG)
    db_session.commit()
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "No domain checks have been recorded" in body  # discovery is not a domain check here


def test_the_domain_page_is_as_private_as_its_assessment(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    mine = create_assessment(db_session, owner, "mine.example", "private")
    scan = scan_service.start_scan(db_session, mine, owner, CONFIG)
    db_session.commit()
    add_domain_result(db_session, scan, "email", email_outcome())

    login_as(client, create_user(db_session))
    assert client.get(f"/assessments/{mine.id}/domain").status_code == 404
    login_as(client, owner)
    assert client.get(f"/assessments/{mine.id}/domain").status_code == 200
    assert client.get(f"/assessments/{uuid.uuid4()}/domain").status_code == 404


def test_hostile_mail_records_are_escaped(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    script = mail_domain()
    script[("example.com", "TXT")] = txt(
        "example.com", f"v=spf1 include:{SCRIPT.replace(' ', '')} -all"
    )
    hostile = ESCAPED
    script[("_dmarc.example.com", "TXT")] = txt(
        "_dmarc.example.com", f"v=DMARC1; p=reject; rua=mailto:{hostile.replace(' ', '')}"
    )
    outcome = email_outcome(script)
    # what the page shows is what DNS said, so build the worst case directly as well
    outcome.data["mx"]["records"][0]["host"] = SCRIPT
    outcome.data["dmarc"]["record"] = SCRIPT
    add_domain_result(db_session, scan, "email", outcome)

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert SCRIPT not in body and body.count(ESCAPED) >= 2
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert SCRIPT not in panel


def test_a_domain_check_without_a_template_still_renders_and_unknown_ones_come_last(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "zzz_future", CheckOutcome("ok", data={"x": 1}))
    add_domain_result(db_session, scan, "email", email_outcome())

    response = client.get(f"/assessments/{assessment.id}/domain")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert body.index('id="check-email"') < body.index('id="check-zzz_future"')
    detail = host_view.get_domain_detail(db_session, scan)
    assert detail is not None and [s.key for s in detail.sections] == ["email", "zzz_future"]


def test_the_domain_rows_leave_out_discovery_and_the_hosts_checks(
    signed_in: Any, db_session: Session
) -> None:
    _, _, scan = signed_in  # starting a scan queued its discovery, a domain-level row too
    add_domain_result(db_session, scan, "email", email_outcome())
    add_host(db_session, scan, WEB_HOST, {"dns": dns_outcome()})

    rows = host_view.domain_rows(db_session, scan.id)
    assert [row.key for row in rows] == ["email"]
    assert rows[0].title == "Email security"


def registration_outcome(domain: str = "example.com", **web_changes: Any) -> CheckOutcome:
    return run_registration(domain, Registry(**web_changes))


def test_the_domain_page_shows_the_registration(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "registration", registration_outcome())

    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Domain registration" in panel and "Expires in " in panel
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert 'id="check-registration"' in body
    assert "RESERVED-Internet Assigned Numbers Authority" in body and "IANA 376" in body
    assert "1995-08-14" in body and "2027-08-13" in body
    assert "client transfer prohibited" in body and "Locked" in body
    assert "Signed" in body  # DNSSEC
    assert (
        "rdap.verisign.com" in body and "Registrant and contact details are not collected" in body
    )
    assert (
        body.index('id="check-email"') < body.index('id="check-registration"')
        if "check-email" in body
        else True
    )


def test_a_registry_without_dates_says_so(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "registration", registration_outcome("admin.ch"))

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "cyon AG" in body and "Not published" in body
    assert "This registry does not publish registration or expiry dates" in body
    assert "Not signed" in body


def test_a_domain_about_to_expire_is_flagged(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    outcome = registration_outcome()
    outcome.data["days_to_expiry"] = 12
    add_domain_result(db_session, scan, "registration", outcome)
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "in 12 days" in body
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert "Expires in 12 days" in panel


def test_why_a_registration_could_not_be_read_is_explained(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(
        db_session,
        scan,
        "registration",
        CheckOutcome("no_data", "no_rdap_service", {"domain": "x.zz", "queried": "x.zz"}),
    )
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "The registry offers no RDAP service" in body and "looked up by hand" in body


def test_hostile_registry_text_is_escaped(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    outcome = registration_outcome()
    outcome.data["registrar"]["name"] = SCRIPT
    outcome.data["statuses"] = [SCRIPT]
    outcome.data["nameservers"] = [SCRIPT]
    outcome.data["server"] = SCRIPT
    add_domain_result(db_session, scan, "registration", outcome)

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert SCRIPT not in body and body.count(ESCAPED) >= 4
    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    assert SCRIPT not in panel


def all_domain_results(session: Session, scan: Scan) -> None:
    """Every domain-level check of a scan with plausible results (the real checks over mocks)."""
    add_domain_result(session, scan, "email", email_outcome())
    add_domain_result(session, scan, "registration", registration_outcome())
    add_domain_result(session, scan, "domain_dns", run_domain_dns(dns_setup())[0])
    add_domain_result(
        session,
        scan,
        "security_txt",
        run_security(Web({("example.com", WELL_KNOWN): security_text(SECURITY_TXT)})),
    )
    add_domain_result(session, scan, "hsts_preload", run_hsts(hsts_answer(HSTS_LISTED)))
    add_domain_result(session, scan, "breaches", run_breaches(breaches_answer(ADOBE)))


@pytest.fixture
def quick_hibp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.checks.breaches.LIMITERS", FakeLimiters())


def test_the_domain_panel_lists_the_checks_in_a_fixed_order(
    signed_in: Any, db_session: Session, quick_hibp: None
) -> None:
    client, assessment, scan = signed_in
    all_domain_results(db_session, scan)

    panel = client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
    titles = [
        "Email security",
        "Domain registration",
        "Name servers and CAA",
        "security.txt",
        "HSTS preload list",
        "Public breach history",
    ]
    positions = [panel.index(title) for title in titles]
    assert positions == sorted(positions)
    for summary in (
        "4 name servers · 2 operators · CAA",
        "Preloaded",
        "1 public breach · 2013-10",
    ):
        assert summary in panel


def test_the_domain_page_shows_name_servers_caa_security_txt_hsts_and_breaches(
    signed_in: Any, db_session: Session, quick_hibp: None
) -> None:
    client, assessment, scan = signed_in
    all_domain_results(db_session, scan)

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    # name servers and CAA
    assert "ns1.provider-a.net" in body and "provider-b.org" in body
    assert "198.51.100.1" in body and "letsencrypt.org" in body and "May issue certificates" in body
    # security.txt
    assert "https://hackerone.com/github" in body and "Not signed" in body
    assert "The addresses in the file are shown as text and are not followed" in body
    # HSTS preload
    assert "Browsers ship this domain on their HSTS preload list" in body
    assert "the domain name was sent to hstspreload.org" in body
    # breaches
    assert "152,445,165" in body and "Passwords" in body and "Verified" in body
    assert "Finding none does not prove that nothing happened" in body
    assert (
        "<a href" not in body.split('id="check-breaches"')[1].split("</section>")[0]
    )  # no HIBP html
    assert body.count("Raw data (JSON)") == 6


def test_a_name_server_operator_alone_is_a_note_not_a_problem(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    from tests.checks.test_domain_dns_check import addresses, ns_records

    script = {
        ("example.com", "NS"): ns_records("example.com", "ns1.example.com", "ns2.example.com"),
        **addresses("ns1.example.com", "198.51.100.1"),
        **addresses("ns2.example.com", "203.0.113.1"),
    }
    add_domain_result(db_session, scan, "domain_dns", run_domain_dns(script)[0])
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "All name servers belong to one operator" in body and "Note" in body
    assert "Without CAA records any certificate authority may issue" in body


def test_security_txt_problems_are_spelled_out(signed_in: Any, db_session: Session) -> None:
    client, assessment, scan = signed_in
    broken = SECURITY_TXT.replace("Contact: https://hackerone.com/github\n", "")
    outcome = run_security(Web({("example.com", WELL_KNOWN): security_text(broken, "text/html")}))
    add_domain_result(db_session, scan, "security_txt", outcome)

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "No Contact field" in body and "Not served as text/plain" in body
    assert "The file is not at any of its own Canonical addresses" in body


def test_a_missing_security_txt_and_a_clean_breach_search_say_so(
    signed_in: Any, db_session: Session, quick_hibp: None
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(db_session, scan, "security_txt", run_security(Web()))
    add_domain_result(db_session, scan, "breaches", run_breaches(breaches_answer([])))
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "No security.txt found" in body
    assert "No public breach known to Have I Been Pwned" in body
    assert "clean" not in body.lower().replace("cleaned", "")  # absence is not "clean"


def test_a_switched_off_third_party_lookup_explains_the_setting(
    signed_in: Any, db_session: Session
) -> None:
    client, assessment, scan = signed_in
    add_domain_result(
        db_session, scan, "hsts_preload", CheckOutcome("unavailable", "disabled", {"domain": "x"})
    )
    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert "Switched off" in body and "EXTERNAL_DOMAIN_LOOKUPS" in body


def test_hostile_text_in_the_new_domain_sections_is_escaped(
    signed_in: Any, db_session: Session, quick_hibp: None
) -> None:
    client, assessment, scan = signed_in
    dns = run_domain_dns(dns_setup())[0]
    dns.data["ns"]["servers"][0]["host"] = SCRIPT
    dns.data["ns"]["servers"][0]["operator"] = SCRIPT
    dns.data["caa"]["records"][0]["value"] = SCRIPT
    dns.data["caa"]["issuers"] = [SCRIPT]
    add_domain_result(db_session, scan, "domain_dns", dns)

    security = run_security(Web({("example.com", WELL_KNOWN): security_text(SECURITY_TXT)}))
    security.data["fields"]["contact"] = [SCRIPT]
    security.data["url"] = SCRIPT
    add_domain_result(db_session, scan, "security_txt", security)

    hsts = run_hsts(hsts_answer(HSTS_LISTED))
    hsts.data["preloaded_domain"] = SCRIPT
    add_domain_result(db_session, scan, "hsts_preload", hsts)

    breaches = run_breaches(breaches_answer(ADOBE))
    breach = breaches.data["breaches"][0]
    breach.update(title=SCRIPT, name=SCRIPT, domain=SCRIPT, data_classes=[SCRIPT])
    add_domain_result(db_session, scan, "breaches", breaches)

    body = client.get(f"/assessments/{assessment.id}/domain").get_data(as_text=True)
    assert SCRIPT not in body and body.count(ESCAPED) >= 8
    assert SCRIPT not in client.get(f"/assessments/{assessment.id}").get_data(as_text=True)
