"""The summary of a scan: coverage, where the data is, who processes it, what is open.

The builders are fed with the real checks' output (the same scripted checks the rule tests use),
so the summary is tested against what the checks really produce.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import Finding, FindingDisposition, Scan
from app.models.base import utc_now
from app.service import findings as findings_service
from app.service import summary
from app.service.geo import IpLocation
from app.service.summary import DomainResult, HostChecks
from tests.checks.test_domain_dns_check import healthy
from tests.checks.test_domain_dns_check import run as run_domain_dns
from tests.checks.test_email_check import mail_domain, policy_site
from tests.checks.test_email_check import run as run_email
from tests.checks.test_ip_check import cloudflare, dns_outcome, german, swiss
from tests.checks.test_registration_check import Registry
from tests.checks.test_registration_check import run as run_registration
from tests.rules import scenario
from tests.rules.helpers import http_only, web
from tests.rules.test_tech_finding_rules import judged as judged_page
from tests.rules.test_tech_finding_rules import script as script_tag
from tests.test_engine import new_scan
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan

ALLOWED = findings_service.allowed_countries({})  # the default area: EU-27, EEA, CH
US = scenario.US


def located(*locations: Any) -> CheckOutcome:
    return scenario.located(*locations)


def checks_of(**outcomes: CheckOutcome) -> HostChecks:
    """What ``load_hosts`` makes of a host's stored results."""
    ip = outcomes.get("ip")
    http = outcomes.get("http")
    return HostChecks(
        statuses={key: (o.status, o.reason_code) for key, o in outcomes.items()},
        location=ip.data if ip is not None and ip.status == "ok" else None,
        scheme=str(http.data.get("scheme")) if http is not None and http.status == "ok" else None,
    )


def domain_of(**outcomes: CheckOutcome) -> dict[str, DomainResult]:
    return {k: DomainResult(o.status, o.reason_code, o.data) for k, o in outcomes.items()}


DNS_OK = dns_outcome("85.1.1.1")
NO_ADDRESS = CheckOutcome("skipped", "no_public_address")


# ------------------------------------------------------------------------------ where


def test_countries_are_counted_by_host_outside_the_allowed_area_first() -> None:
    hosts = [
        checks_of(dns=DNS_OK, ip=located(swiss())),
        checks_of(dns=DNS_OK, ip=located(swiss("85.1.1.2"), german())),
        checks_of(dns=DNS_OK, ip=located(german("46.4.0.2"))),
        checks_of(dns=DNS_OK, ip=located(US)),
    ]
    where = summary.where_of(hosts, ALLOWED)

    assert [(c.code, c.name, c.hosts, c.allowed) for c in where.countries] == [
        ("US", "United States", 1, False),  # outside the allowed area: first
        ("DE", "Germany", 2, True),
        ("CH", "Switzerland", 2, True),
    ]
    assert where.located == 4 and where.outside == 1 and where.outside_edge_only == 0
    cities = {c.code: c.cities for c in where.countries}
    assert cities == {
        "US": (("Ashburn", 1),),
        "DE": (("Falkenstein", 2),),
        "CH": (("Bern", 2),),
    }
    assert where.allowed_count == len(ALLOWED) and where.rule_id == "LOCATION_OUTSIDE_EU_CH"


def test_a_host_with_addresses_in_two_countries_counts_once_in_each() -> None:
    both = checks_of(dns=DNS_OK, ip=located(swiss(), german()))
    where = summary.where_of([both], ALLOWED)
    assert [(c.code, c.hosts) for c in where.countries] == [("DE", 1), ("CH", 1)]
    assert where.located == 1  # one host, however many places


def test_the_allowed_area_is_the_configured_one() -> None:
    hosts = [checks_of(dns=DNS_OK, ip=located(US)), checks_of(dns=DNS_OK, ip=located(swiss()))]
    assert summary.where_of(hosts, ALLOWED).outside == 1
    wider = findings_service.allowed_countries({"DATA_LOCATION_ALLOWED": ["ch", "us"]})
    where = summary.where_of(hosts, wider)
    assert where.outside == 0 and all(c.allowed for c in where.countries)
    assert where.allowed_count == 2  # codes are upper-cased


def test_a_cdn_edge_is_not_a_place() -> None:
    """Cloudflare's address geolocates to Toronto: that is the edge, not where the data is."""
    behind_cdn = checks_of(dns=DNS_OK, ip=located(cloudflare()))
    where = summary.where_of([behind_cdn, behind_cdn], ALLOWED)

    assert where.countries == () and where.located == 0
    assert where.edge_hosts == 2 and where.edge_networks == (("Cloudflare", 2),)
    assert (where.outside, where.outside_edge_only) == (0, 2)  # outside only through an edge


def test_a_host_with_an_origin_and_an_edge_is_placed_by_its_origin() -> None:
    mixed = checks_of(dns=DNS_OK, ip=located(swiss(), cloudflare()))
    where = summary.where_of([mixed], ALLOWED)
    assert [(c.code, c.hosts) for c in where.countries] == [("CH", 1)]
    assert (where.edge_hosts, where.outside, where.outside_edge_only) == (0, 0, 1)


def test_the_summary_agrees_with_the_rule_about_who_is_outside() -> None:
    """Same facts, same area: the card counts the hosts for which the rule files a finding."""
    from app.rules import RULES, HostFacts, Result
    from tests.rules.helpers import settings

    cases = {
        "origin outside": located(US),
        "edge outside": located(cloudflare()),
        "origin inside, edge outside": located(swiss(), cloudflare()),
        "inside": located(swiss()),
    }
    for name, outcome in cases.items():
        host = HostFacts("h", "h.example.com", "ct", {"ip": Result("r", "ok", None, outcome.data)})
        findings = list(RULES["LOCATION_OUTSIDE_EU_CH"].evaluate(host, settings()))
        where = summary.where_of([checks_of(dns=DNS_OK, ip=outcome)], ALLOWED)
        assert (where.outside + where.outside_edge_only == 1) == bool(findings), name
        if findings:
            assert (where.outside == 1) == (not findings[0].params["edge_only"]), name


def test_hosts_that_could_not_be_located_are_counted_with_their_reason() -> None:
    hosts = [
        checks_of(dns=DNS_OK, ip=CheckOutcome("unavailable", "datasets_missing")),
        checks_of(dns=DNS_OK, ip=CheckOutcome("unavailable", "datasets_missing")),
        checks_of(dns=DNS_OK, ip=CheckOutcome("no_data", "not_in_database")),
        checks_of(dns=NO_ADDRESS, ip=NO_ADDRESS),  # no address to place: not a gap of the location
        checks_of(dns=DNS_OK, ip=located(swiss())),
    ]
    where = summary.where_of(hosts, ALLOWED)
    assert where.unlocated == 3 and where.unlocated_reason == "datasets_missing"
    assert where.located == 1


def test_an_address_the_databases_know_only_by_network_is_not_placed() -> None:
    network_only = IpLocation("203.0.113.9", asn=64500, organisation="Example Net")
    where = summary.where_of([checks_of(dns=DNS_OK, ip=located(network_only))], ALLOWED)
    assert where.countries == () and where.unlocated == 1
    assert where.unlocated_reason == "no_country"


def test_the_lists_are_bounded() -> None:
    def in_country(n: int) -> HostChecks:  # shaped like an ``ip`` result, without running the check
        entry = {"ip": f"10.0.{n}.1", "country": f"X{n:02d}", "country_name": f"Land {n:02d}"}
        return HostChecks({"ip": ("ok", None)}, {"addresses": [entry]})

    many = [in_country(n) for n in range(summary.MAX_COUNTRIES + 5)]
    where = summary.where_of(many, frozenset())
    assert len(where.countries) == summary.MAX_COUNTRIES and where.more_countries == 5


def test_an_empty_scan_places_nothing() -> None:
    where = summary.where_of([], ALLOWED)
    assert (where.countries, where.located, where.outside, where.unlocated) == ((), 0, 0, 0)


# ------------------------------------------------------------------------------ who


def test_the_networks_of_the_addresses_are_grouped_and_busiest_first() -> None:
    hosts = [
        checks_of(dns=DNS_OK, ip=located(swiss())),
        checks_of(dns=DNS_OK, ip=located(swiss("85.1.1.2"))),
        checks_of(dns=DNS_OK, ip=located(german())),
        checks_of(dns=DNS_OK, ip=located(cloudflare())),
        checks_of(dns=DNS_OK, ip=located(US)),  # no network record at all: nothing to name
    ]
    who = summary.who_of(hosts, {})
    assert [(n.name, n.kind, n.asns, n.hosts) for n in who.networks] == [
        ("Swisscom", None, (3303,), 2),
        ("Cloudflare", "cdn", (13335,), 1),
        ("Hetzner", "hosting", (24940,), 1),
    ]
    assert who.networks_reason is None and who.addressed == 5


def test_addresses_without_a_network_record_name_no_network() -> None:
    bare = IpLocation("203.0.113.10", "CH", "Switzerland", "EU", "Bern", "Bern", 0.0, 0.0)
    who = summary.who_of([checks_of(dns=DNS_OK, ip=located(bare))], {})
    assert who.networks == () and who.networks_reason is None and who.addressed == 1


def test_hosting_that_could_not_be_looked_up_says_why_not_none() -> None:
    hosts = [checks_of(dns=DNS_OK, ip=CheckOutcome("unavailable", "datasets_missing"))]
    who = summary.who_of(hosts, {})
    assert who.networks == () and who.networks_reason == "datasets_missing"
    assert summary.who_of([], {}).networks_reason is None  # nothing to look up: nothing missing


def test_the_domain_records_name_dns_operators_mail_providers_senders_and_registrar() -> None:
    domain = domain_of(
        domain_dns=run_domain_dns(healthy())[0],
        email=run_email(mail_domain(), policy_site)[0],
        registration=run_registration("example.com", Registry()),
    )
    who = summary.who_of([], domain)

    assert who.dns == summary.Group("found", (("provider-a.net", 2), ("provider-b.org", 2)))
    assert who.mail == summary.Group("found", (("Google Workspace", 2),))  # two MX hosts
    assert who.senders == summary.Group("found", (("Google Workspace", None),))
    assert who.registrar.state == "found"
    assert who.registrar.items[0][0] == "RESERVED-Internet Assigned Numbers Authority"


def test_an_mx_host_nobody_recognises_is_named_by_its_registrable_domain() -> None:
    data = {"mx": {"found": True, "records": [{"preference": 10, "host": "mx1.mail.example.org."}]}}
    who = summary.who_of([], {"email": DomainResult("ok", None, data)})
    assert who.mail.items == (("example.org", 1),)


def test_what_could_not_be_asked_is_not_determined_never_none() -> None:
    who = summary.who_of(
        [],
        domain_of(
            email=CheckOutcome("error", "timeout"),
            domain_dns=CheckOutcome("unavailable", "disabled"),
        ),
    )
    assert who.mail == summary.Group("unknown", reason="timeout")
    assert who.senders == summary.Group("unknown", reason="timeout")
    assert who.dns == summary.Group("unknown", reason="disabled")
    assert who.registrar == summary.Group("unknown", reason="not_run")  # no such result at all

    partly = DomainResult("ok", None, {"mx": {"found": None, "error": "timeout"}, "spf": {}})
    who = summary.who_of([], {"email": partly})
    assert who.mail == summary.Group("unknown", reason="not_determined")
    assert who.senders == summary.Group("unknown", reason="not_determined")


def test_a_domain_without_mail_or_registrar_data_has_none_not_unknown() -> None:
    quiet = domain_of(
        email=CheckOutcome(
            "ok", data={"mx": {"found": False, "records": []}, "spf": {"found": False}}
        ),
        registration=CheckOutcome("ok", data={"registrar": None}),
        domain_dns=CheckOutcome("ok", data={"ns": {"found": False}}),
    )
    who = summary.who_of([], quiet)
    assert (who.mail.state, who.senders.state, who.registrar.state, who.dns.state) == ("none",) * 4


def test_the_provider_lists_are_bounded() -> None:
    records = [{"preference": n, "host": f"mx.provider{n}.example"} for n in range(12)]
    data: dict[str, Any] = {"mx": {"found": True, "records": records}}
    who = summary.who_of([], {"email": DomainResult("ok", None, data)})
    assert len(who.mail.items) == summary.MAX_ITEMS and who.mail.more == 4


# ----- what the pages show: the CDN or WAF in front, the services they load


def seen(
    edge: tuple[str, ...] = (),
    services: tuple[tuple[str, str | None], ...] = (),
    *,
    read: bool = True,
) -> HostChecks:
    """A host whose technology check ended with an answer."""
    return HostChecks(
        {"tech": ("ok", None)}, platforms=summary.Platforms(edge, services, page_read=read)
    )


def test_the_edge_and_the_services_are_counted_by_host_busiest_first() -> None:
    analytics = ("Google Analytics (gtag.js)", "Google")
    hosts = [
        seen(("Cloudflare",), (analytics, ("Hotjar", "Hotjar"), ("Facebook Pixel", "Meta"))),
        seen(("Cloudflare", "Cloudflare"), (analytics, analytics)),  # twice on one host: once
        seen(("Akamai",), ()),
    ]
    who = summary.who_of(hosts, {})
    assert who.edge == summary.Group("found", (("Cloudflare", 2), ("Akamai", 1)))
    assert who.services == summary.Group(
        "found",
        (
            ("Google Analytics (gtag.js)", 2),  # the vendor is already in the name
            ("Facebook Pixel (Meta)", 1),  # the vendor processes, the name says what
            ("Hotjar", 1),
        ),
    )
    assert (who.pages_read, who.pages_analysed) == (3, 3)


def test_pages_that_could_not_be_read_say_nothing_about_the_services_they_load() -> None:
    nothing = [seen(read=False), seen(read=False)]
    who = summary.who_of(nothing, {})
    assert who.edge == summary.Group("none")  # DNS, headers and networks were looked at
    assert who.services == summary.Group("unknown", reason="no_page")  # the page is where they are
    assert (who.pages_read, who.pages_analysed) == (0, 2)

    one_page = summary.who_of([*nothing, seen()], {})
    assert one_page.services == summary.Group("none")  # a page that was read shows none
    assert (one_page.pages_read, one_page.pages_analysed) == (1, 3)

    platform = summary.who_of([seen(services=(("Shopify", "Shopify"),), read=False)], {})
    assert platform.services.items == (("Shopify", 1),)  # a header can show it without the page


def test_without_a_technology_result_the_platforms_are_not_determined_never_none() -> None:
    who = summary.who_of([checks_of(dns=DNS_OK)], {})
    assert who.edge == who.services == summary.Group("unknown", reason="not_run")
    assert (who.pages_read, who.pages_analysed) == (0, 0)

    failed = HostChecks({"tech": ("error", "timeout")})
    skipped = HostChecks({"tech": ("skipped", "no_public_address")})
    who = summary.who_of([failed, failed, skipped], {})
    assert who.edge == who.services == summary.Group("unknown", reason="timeout")  # the common one
    assert summary.who_of([], {}).edge == summary.Group("unknown", reason="not_run")


def test_the_services_are_bounded() -> None:
    many = seen(services=tuple((f"Service {n:02d}", f"Vendor {n:02d}") for n in range(20)))
    who = summary.who_of([many], {})
    assert len(who.services.items) == summary.MAX_SERVICES and who.services.more == 8
    crowded = seen(tuple(f"Edge {n}" for n in range(11)))
    assert len(summary.who_of([crowded], {}).edge.items) == summary.MAX_ITEMS


def test_the_platforms_of_a_host_are_read_from_its_stored_technology_result(
    db_session: Session,
) -> None:
    page = judged_page(
        script_tag("https://www.googletagmanager.com/gtm.js?id=GTM-ABC"),
        headers=[("CF-RAY", "7d1-FRA"), ("Server", "cloudflare")],
    )
    scan = new_scan(db_session, "example.com")
    stored = {
        key: CheckOutcome(r.status, r.reason_code, dict(r.data)) for key, r in page.results.items()
    }
    add_host(db_session, scan, "www.example.com", stored)
    add_host(db_session, scan, "old.example.com", {"dns": CheckOutcome("no_data", "nxdomain")})

    loaded = {h.platforms is not None: h for h in summary.load_hosts(db_session, scan.id)}
    assert set(loaded) == {True, False}  # the host without a technology result has none
    platforms = loaded[True].platforms
    assert platforms is not None and platforms.page_read is True
    assert platforms.edge == ("Cloudflare",)
    assert ("Google Tag Manager", "Google") in platforms.services

    who = summary.who_of(list(loaded.values()), {})
    assert who.edge == summary.Group("found", (("Cloudflare", 1),))
    assert (who.pages_read, who.pages_analysed) == (1, 1)


def test_a_malformed_technology_result_counts_as_nothing_seen() -> None:
    assert summary._platforms("x", {"a": 1}, "yes") == summary.Platforms((), (), False)
    assert summary._platforms(["Cloudflare"], [{"vendor": "v"}, "x", {"name": "n"}], True) == (
        summary.Platforms(("Cloudflare",), (("n", None),), True)
    )


# ------------------------------------------------------------------------------ coverage


def test_every_host_lands_in_exactly_one_web_state() -> None:
    https = checks_of(dns=DNS_OK, http=web())
    plain = checks_of(dns=DNS_OK, http=http_only())
    closed = checks_of(dns=DNS_OK, http=CheckOutcome("no_data", "no_web_server"))
    gone = checks_of(
        dns=CheckOutcome("no_data", "nxdomain"), http=CheckOutcome("skipped", "needs:dns")
    )
    private = checks_of(dns=DNS_OK, http=NO_ADDRESS)
    broken = checks_of(dns=DNS_OK, http=CheckOutcome("error", "timeout"))
    unknown = checks_of(dns=CheckOutcome("error", "servfail"))
    hosts = [https, https, plain, closed, gone, private, broken, unknown]

    coverage = summary.coverage_of(hosts, {})
    assert (coverage.https, coverage.http_only, coverage.no_web_server) == (2, 1, 1)
    assert (coverage.no_address, coverage.undetermined) == (2, 2)
    assert (
        coverage.https + coverage.http_only + coverage.not_reachable + coverage.undetermined
        == len(hosts)
    )
    assert coverage.hosts == 8 and coverage.not_reachable == 3


def test_a_host_is_fully_checked_when_nothing_failed_and_nothing_is_missing() -> None:
    fine = checks_of(dns=DNS_OK, http=web(), ip=located(swiss()))
    nothing_there = checks_of(
        dns=CheckOutcome("no_data", "nxdomain"), tls=CheckOutcome("skipped", "needs:dns")
    )  # a name that does not exist was fully checked
    failed = checks_of(dns=DNS_OK, tls=CheckOutcome("error", "timeout"))
    unavailable = checks_of(dns=DNS_OK, ip=CheckOutcome("unavailable", "datasets_missing"))
    unfinished = checks_of(dns=DNS_OK, http=CheckOutcome("running", None))
    cancelled = checks_of(dns=DNS_OK, http=CheckOutcome("skipped", "scan_cancelled"))
    no_rows = HostChecks({})

    hosts = [fine, nothing_there, failed, unavailable, unfinished, cancelled, no_rows]
    coverage = summary.coverage_of(hosts, {})
    assert coverage.fully_checked == 2 and coverage.incomplete == 5


def test_what_discovery_saw_and_left_out() -> None:
    discovery = {
        "counts": {"names_seen": 148, "out_of_scope": 9},
        "wildcard_patterns": ["*.example.com", "*.dev.example.com"],
        "planned": {"dropped_by_cap": 22},
    }
    coverage = summary.coverage_of([], discovery, host_limit=200)
    assert coverage.names_seen == 148 and coverage.host_limit == 200
    assert (coverage.out_of_scope, coverage.wildcards, coverage.over_limit) == (9, 2, 22)
    assert coverage.not_reviewed == 33


def test_hosts_over_the_limit_are_those_dropped_in_discovery_and_those_dropped_in_the_plan() -> (
    None
):
    """Discovery caps what its sources returned; the plan then puts the domain and the hosts added
    by hand first and may drop more. Both are hosts nobody reviewed."""
    discovery = {
        "counts": {"names_seen": 9977, "out_of_scope": 0, "dropped_by_cap": 9964},
        "wildcard_patterns": ["*.example.com"],
        "planned": {"hosts": 12, "dropped_by_cap": 3},
    }
    assert summary.hosts_over_limit(discovery) == 9967
    coverage = summary.coverage_of([], discovery, host_limit=12)
    assert coverage.over_limit == 9967 and coverage.not_reviewed == 9968
    assert summary.hosts_over_limit({"counts": {"dropped_by_cap": 5}}) == 5
    assert summary.hosts_over_limit({"planned": {"dropped_by_cap": 4}}) == 4


@pytest.mark.parametrize(
    "discovery",
    [
        {},
        {"counts": [], "planned": "x", "wildcard_patterns": 3},
        {"counts": {"names_seen": "many", "dropped_by_cap": "lots"}},
    ],
)
def test_a_discovery_record_that_is_missing_or_malformed_counts_as_zero(
    discovery: dict[str, Any],
) -> None:
    coverage = summary.coverage_of([], discovery)
    assert (coverage.names_seen, coverage.not_reviewed, coverage.hosts) == (0, 0, 0)


# ------------------------------------------------------------------------------ open findings


def evaluated(session: Session, domain: str = "example.com") -> tuple[Scan, dict[str, Finding]]:
    """A finished scan with its findings, keyed ``RULE:subject``."""
    scan, _ = populated_scan(session, domain)
    findings_service.evaluate_scan(session, scan, RULES_CONFIG)
    scan.status, scan.finished_at = "completed", utc_now()
    session.commit()
    found = session.scalars(select(Finding).where(Finding.scan_id == scan.id))
    return scan, {f"{f.rule_id}:{f.subject}": f for f in found}


def decide(
    session: Session,
    scan: Scan,
    finding: Finding,
    status: str,
    review_by: date | None = None,
) -> None:
    session.add(
        FindingDisposition(
            assessment_id=scan.assessment_id,
            fingerprint=finding.fingerprint,
            status=status,
            reason="because",
            decided_by=scan.requested_by,
            review_by=review_by,
        )
    )
    session.commit()


def test_with_no_decisions_every_finding_is_open(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    tally = findings_service.tally(db_session, scan)
    assert tally.open_total == len(rows) and (tally.accepted, tally.false_positive) == (0, 0)
    assert tally.open_by_severity == findings_service.breakdown(db_session, scan).by_severity("all")
    assert sum(rule.count for rule in tally.open_rules) == len(rows)


def test_decided_findings_leave_the_open_counts_but_are_counted_apart(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    everything = findings_service.tally(db_session, scan)
    today = utc_now().date()
    decide(
        db_session,
        scan,
        rows["SPF_MISSING:domain:example.com"],
        "accepted",
        today + timedelta(days=30),
    )
    decide(db_session, scan, rows["DMARC_MISSING:domain:example.com"], "false_positive")
    decide(db_session, scan, rows["TLS_INVALID:host:bad-tls.example.com"], "accepted")  # no date

    after = findings_service.tally(db_session, scan)
    assert (after.accepted, after.false_positive) == (2, 1)
    assert after.open_total == everything.open_total - 3
    assert after.open_by_severity["high"] == everything.open_by_severity["high"] - 1  # TLS_INVALID
    assert "SPF_MISSING" not in {r.rule_id for r in after.open_rules}


def test_an_acceptance_whose_review_date_has_passed_is_open_again(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    today = utc_now().date()
    decide(
        db_session,
        scan,
        rows["SPF_MISSING:domain:example.com"],
        "accepted",
        today - timedelta(days=1),
    )
    decide(
        db_session, scan, rows["DMARC_MISSING:domain:example.com"], "accepted", today
    )  # still valid today
    decide(
        db_session,
        scan,
        rows["TLS_INVALID:host:bad-tls.example.com"],
        "false_positive",
        today - timedelta(days=9),
    )

    tally = findings_service.tally(db_session, scan, today=today)
    assert tally.accepted == 1  # the one that is still valid
    assert tally.false_positive == 1  # a false positive does not expire
    rules = {r.rule_id for r in tally.open_rules}
    assert "SPF_MISSING" in rules  # reopened
    assert "DMARC_MISSING" not in rules
    # the same decisions, seen from a later day
    later = findings_service.tally(db_session, scan, today=today + timedelta(days=2))
    assert later.accepted == 0 and "DMARC_MISSING" in {r.rule_id for r in later.open_rules}


def test_a_decision_belongs_to_its_assessment_only(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    other, other_rows = evaluated(db_session)  # another assessment, the same facts
    decide(db_session, scan, rows["SPF_MISSING:domain:example.com"], "accepted")
    assert findings_service.tally(db_session, scan).accepted == 1
    assert findings_service.tally(db_session, other).accepted == 0
    assert (
        other_rows["SPF_MISSING:domain:example.com"].fingerprint
        == rows["SPF_MISSING:domain:example.com"].fingerprint
    )


def test_a_decision_made_earlier_carries_over_to_a_later_scan(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    decide(db_session, scan, rows["SPF_MISSING:domain:example.com"], "accepted")

    # the next scan of the same assessment finds the same thing: same rule, same subject
    follow = Scan(
        assessment_id=scan.assessment_id,
        requested_by=scan.requested_by,
        status="completed",
        options={},
    )
    db_session.add(follow)
    db_session.flush()
    again = rows["SPF_MISSING:domain:example.com"]
    db_session.add(
        Finding(
            scan_id=follow.id, host_id=None, rule_id=again.rule_id, rule_version="1",
            subject=again.subject, severity=again.severity, confidence=again.confidence,
            attribution=again.attribution, params={}, evidence=[], fingerprint=again.fingerprint,
        )
    )  # fmt: skip
    follow.summary = {"findings": {"total": 1}}
    db_session.commit()

    carried = findings_service.tally(db_session, follow)
    assert (carried.accepted, carried.open_total) == (1, 0)


# ------------------------------------------------------------------------------ one scan, loaded


def test_the_summary_of_a_scan_is_built_from_what_is_stored(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    decide(db_session, scan, rows["SPF_MISSING:domain:example.com"], "accepted")
    discovery = {"counts": {"names_seen": 7, "out_of_scope": 1}, "planned": {"dropped_by_cap": 0}}

    built = summary.build_summary(db_session, scan, discovery, ALLOWED)

    coverage = built.coverage
    assert (coverage.hosts, coverage.names_seen, coverage.out_of_scope) == (4, 7, 1)
    assert (coverage.https, coverage.http_only, coverage.undetermined) == (
        2,
        1,
        1,
    )  # cdn: no web check
    assert coverage.host_limit == 200  # from the scan's options

    where = built.where
    assert {c.code for c in where.countries} == {"US", "CH"}  # plain.example.com has both
    assert where.edge_hosts == 1 and where.edge_networks == (("Cloudflare", 1),)
    assert (where.outside, where.outside_edge_only) == (1, 1)

    who = built.who
    assert {n.name for n in who.networks} == {"Swisscom", "Cloudflare"}
    assert who.registrar.state == "found" and who.mail.items == (("Google Workspace", 2),)
    assert who.dns == summary.Group("unknown", reason="not_run")  # this scan stored no such check
    assert who.edge == who.services == summary.Group("unknown", reason="not_run")  # nor this one

    secure = built.secure
    assert secure.state == "ready" and secure.accepted == 1
    assert secure.hosts == 4 and secure.fully_checked == coverage.fully_checked
    assert 0 < len(secure.top_rules) <= summary.MAX_TOP_RULES
    assert secure.top_rules[0].severity == "high"  # the most serious open rule first


def test_a_scan_that_is_not_evaluated_has_no_open_counts_to_show(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    scan.status = "cancelled"
    built = summary.build_summary(db_session, scan, {}, ALLOWED)
    assert built.secure.state == "not_evaluated" and built.secure.open_total == 0
    assert built.secure.hosts == 4  # what was looked at is still reported
    assert built.coverage.hosts == 4 and built.where.countries  # and so is where the hosts are


def test_hosts_without_any_check_result_are_a_gap_not_a_success(db_session: Session) -> None:
    scan = new_scan(db_session)
    add_host(db_session, scan, "silent.example.com", {})
    built = summary.build_summary(db_session, scan, {}, ALLOWED)
    assert (built.coverage.hosts, built.coverage.fully_checked) == (1, 0)
    assert built.coverage.undetermined == 1
