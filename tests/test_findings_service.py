"""Findings in the database: evaluation when a scan finishes, replacement, reading, describing."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from flask.testing import FlaskCliRunner
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.service.findings as findings_service
from app.checks.base import CheckOutcome
from app.models import CheckResult, Finding, Host, Scan
from app.models.base import utc_now
from app.service import scans as scan_service
from app.service import worker
from tests.helpers import create_assessment, create_user
from tests.rules import scenario
from tests.test_engine import CONFIG, FakeCheck, discovery, drain, new_scan

RULES_CONFIG: dict[str, Any] = {
    **CONFIG,
    "DATA_LOCATION_ALLOWED": ["CH", "DE"],
    "BREACH_RECENT_MONTHS": 24,
}


def add_host(session: Session, scan: Scan, hostname: str, results: dict[str, CheckOutcome]) -> Host:
    host = Host(scan_id=scan.id, hostname=hostname, source="ct", ct_sources=["ctlogs"])
    session.add(host)
    session.flush()
    for key, outcome in results.items():
        session.add(
            CheckResult(
                scan_id=scan.id,
                host_id=host.id,
                check_key=key,
                status=outcome.status,
                reason_code=outcome.reason_code,
                data=outcome.data,
                source=outcome.source,
                collected_at=utc_now(),
            )
        )
    session.commit()
    return host


def add_domain(session: Session, scan: Scan, results: dict[str, CheckOutcome]) -> None:
    for key, outcome in results.items():
        session.add(
            CheckResult(
                scan_id=scan.id,
                host_id=None,
                check_key=key,
                status=outcome.status,
                reason_code=outcome.reason_code,
                data=outcome.data,
                source=outcome.source,
                collected_at=utc_now(),
            )
        )
    session.commit()


def populated_scan(session: Session, domain: str = "example.com") -> tuple[Scan, dict[str, Host]]:
    scan = new_scan(session, domain)
    hosts = {
        h.hostname: add_host(
            session,
            scan,
            h.hostname,
            {
                key: CheckOutcome(r.status, r.reason_code, dict(r.data))
                for key, r in h.results.items()
            },
        )
        for h in scenario.hosts()
    }
    add_domain(
        session,
        scan,
        {
            "email": scenario.domain_with_gaps()["email"],
            "registration": scenario.domain_with_gaps()["registration"],
            "security_txt": scenario.domain_with_gaps()["security_txt"],
        },
    )
    return scan, hosts


def stored(session: Session, scan: Scan) -> list[Finding]:
    return list(session.scalars(select(Finding).where(Finding.scan_id == scan.id)))


# ----- evaluating


def test_evaluating_a_scan_stores_findings_that_point_at_their_evidence(
    db_session: Session,
) -> None:
    scan, hosts = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()

    rows = stored(db_session, scan)
    assert summary.total == len(rows) > 10
    rules = {row.rule_id for row in rows}
    assert {"TLS_INVALID", "SPF_MISSING", "DMARC_MISSING", "LOCATION_OUTSIDE_EU_CH"} <= rules
    assert len({row.fingerprint for row in rows}) == len(rows)  # one finding per fingerprint

    tls = next(r for r in rows if r.rule_id == "TLS_INVALID")
    assert tls.host_id == hosts["bad-tls.example.com"].id
    assert (tls.severity, tls.confidence, tls.attribution) == ("high", "high", "hostname_supported")
    assert tls.subject == "host:bad-tls.example.com" and tls.rule_version == "1"

    spf = next(r for r in rows if r.rule_id == "SPF_MISSING")
    assert spf.host_id is None and spf.attribution == "domain"

    for row in rows:  # evidence ids are real results of this scan
        for evidence_id in row.evidence:
            result = db_session.get(CheckResult, uuid.UUID(evidence_id))
            assert result is not None and result.scan_id == scan.id


def test_address_level_findings_belong_to_no_single_host_but_name_theirs(
    db_session: Session,
) -> None:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    risky = next(
        r
        for r in stored(db_session, scan)
        if r.rule_id == "RISKY_PORT_EXPOSED" and r.params["port"] == 22
    )
    assert risky.host_id is None and risky.subject == "ip:93.184.216.34:22"
    assert risky.params["host_ids"] == [str(hosts["bad-tls.example.com"].id)]


def test_the_summary_of_the_evaluation_is_kept_on_the_scan(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    db_session.refresh(scan)

    stored_summary = scan.summary["findings"]
    assert stored_summary["total"] == summary.total
    assert stored_summary["by_severity"] == summary.by_severity
    assert list(summary.by_severity) == sorted(
        summary.by_severity, key=findings_service.SEVERITIES.index
    )
    assert stored_summary["ruleset"] == findings_service.ruleset_digest()
    assert stored_summary["errors"] == [] and stored_summary["dropped"] == 0
    assert stored_summary["evaluated_at"]


def test_evaluating_again_replaces_the_findings_and_keeps_other_summary_keys(
    db_session: Session,
) -> None:
    scan, hosts = populated_scan(db_session)
    scan.summary = {"cards": {"where": 1}}
    first = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    ids = {row.id for row in stored(db_session, scan)}

    # the world changes: the certificate is renewed
    tls = db_session.scalars(
        select(CheckResult).where(
            CheckResult.host_id == hosts["bad-tls.example.com"].id, CheckResult.check_key == "tls"
        )
    ).one()
    tls.data = {**tls.data, "verified": True, "failures": []}
    db_session.commit()

    second = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    rows = stored(db_session, scan)
    assert second.total == first.total - 1 and "TLS_INVALID" not in {r.rule_id for r in rows}
    assert not ids & {row.id for row in rows}  # replaced, not appended to
    assert (
        scan.summary["cards"] == {"where": 1} and scan.summary["findings"]["total"] == second.total
    )


def test_other_scans_keep_their_findings(db_session: Session) -> None:
    old, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, old, RULES_CONFIG)
    db_session.commit()
    before = {row.id for row in stored(db_session, old)}

    user = create_user(db_session)
    other = create_assessment(db_session, user, "other.example")
    new = scan_service.start_scan(db_session, other, user, CONFIG)
    db_session.commit()
    findings_service.evaluate_scan(db_session, new, RULES_CONFIG)
    db_session.commit()

    assert {row.id for row in stored(db_session, old)} == before
    assert stored(db_session, new) == []  # a scan with no results has no findings


def test_checks_that_have_not_finished_are_not_facts(db_session: Session) -> None:
    scan = new_scan(db_session)
    pending = CheckOutcome("ok", data=scenario.domain_with_gaps()["email"].data)
    for status in ("queued", "running"):
        db_session.add(
            CheckResult(
                scan_id=scan.id,
                host_id=None,
                check_key=f"email_{status}",
                status=status,
                data=pending.data,
            )
        )
    db_session.commit()
    # (the real key is "email"; a pending row of that key must be ignored too)
    row = db_session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id, CheckResult.check_key == "discovery"
        )
    ).one()
    row.data = {"hosts": []}
    db_session.commit()
    facts = findings_service.load_facts(db_session, scan)
    assert (
        facts.domain_results == {}
    )  # discovery is not a domain check; pending rows are not results


def test_the_allowed_area_comes_from_the_configuration(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(
        db_session, scan, {**RULES_CONFIG, "DATA_LOCATION_ALLOWED": ["CH", "DE", "US", "CA"]}
    )
    assert "LOCATION_OUTSIDE_EU_CH" not in {r.rule_id for r in stored(db_session, scan)}
    findings_service.evaluate_scan(
        db_session, scan, {**RULES_CONFIG, "DATA_LOCATION_ALLOWED": ["CH", "DE"]}
    )
    assert "LOCATION_OUTSIDE_EU_CH" in {r.rule_id for r in stored(db_session, scan)}


def test_without_configuration_the_default_area_applies_not_an_empty_one(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, CONFIG)  # no area configured
    swiss_only = {
        r.subject for r in stored(db_session, scan) if r.rule_id == "LOCATION_OUTSIDE_EU_CH"
    }
    assert (
        summary.total > 0 and "host:plain.example.com" in swiss_only
    )  # the US address, not the Swiss one
    assert "host:bad-tls.example.com" not in swiss_only


def test_a_rule_that_crashes_is_reported_and_the_rest_is_stored(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.rules import RULES

    def boom(*args: Any) -> list[Any]:
        raise RuntimeError("boom")

    monkeypatch.setitem(
        RULES,
        "TLS_INVALID",
        RULES["TLS_INVALID"].__class__(**{**RULES["TLS_INVALID"].__dict__, "evaluate": boom}),
    )
    scan, _ = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    assert summary.errors == ["TLS_INVALID"] and summary.total > 5
    assert "TLS_INVALID" not in {r.rule_id for r in stored(db_session, scan)}


# ----- when a scan finishes


class Dangling(FakeCheck):
    """A DNS stand-in whose answer trips a rule."""

    def __init__(self) -> None:
        super().__init__(
            "dns",
            "host",
            CheckOutcome(
                "ok",
                data={
                    "dangling_cname": True,
                    "canonical_name": "gone.example.net",
                    "addresses": [],
                    "blocked": [],
                },
            ),
        )


def test_a_scan_evaluates_its_rules_when_its_last_check_finishes(db_session: Session) -> None:
    scan = new_scan(db_session)
    registry = {"discovery": discovery("www.example.com"), "dns": Dangling()}
    drain(db_session, registry, RULES_CONFIG)
    db_session.refresh(scan)

    assert scan.status == "completed"
    rows = stored(db_session, scan)
    assert {r.rule_id for r in rows} == {"DANGLING_CNAME"} and len(rows) == 2  # apex and www
    assert scan.summary["findings"]["total"] == 2
    assert scan.summary["findings"]["by_severity"] == {"medium": 2}


def test_a_scan_that_is_not_finished_has_no_findings_yet(db_session: Session) -> None:
    scan = new_scan(db_session)
    registry = {"discovery": discovery("www.example.com"), "dns": Dangling()}
    http = worker.httpx.Client(
        transport=worker.httpx.MockTransport(lambda r: worker.httpx.Response(500))
    )
    worker.process_one(
        db_session, "w", config=RULES_CONFIG, http=http, registry=registry
    )  # discovery only
    db_session.refresh(scan)
    assert not scan.is_terminal and stored(db_session, scan) == []


def test_a_failing_evaluation_never_fails_the_scan(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("the rules are on fire")

    monkeypatch.setattr(findings_service, "evaluate_scan", broken)
    scan = new_scan(db_session)
    drain(db_session, {"discovery": discovery(), "dns": Dangling()}, RULES_CONFIG)
    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.summary == {"findings": {"error": "evaluation_failed"}}
    assert stored(db_session, scan) == []


def test_a_database_error_in_the_rules_loses_the_findings_only(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import IntegrityError

    original = findings_service._row

    def clash(scan: Scan, finding: Any) -> Finding:
        row = original(scan, finding)
        row.severity = "not-a-severity"  # violates the table's check constraint at flush
        return row

    monkeypatch.setattr(findings_service, "_row", clash)
    scan = new_scan(db_session)
    drain(db_session, {"discovery": discovery(), "dns": Dangling()}, RULES_CONFIG)
    db_session.refresh(scan)
    assert scan.status == "completed" and scan.summary["findings"] == {"error": "evaluation_failed"}
    assert IntegrityError is not None


def test_a_cancelled_scan_gets_no_findings(db_session: Session) -> None:
    scan = new_scan(db_session)
    assert scan_service.cancel_active_scan(db_session, scan.assessment_id) is True
    db_session.commit()
    assert scan_service.finalize_scan_if_done(db_session, scan.id, RULES_CONFIG) is not None
    assert stored(db_session, scan) == []


# ----- reading


def test_findings_are_listed_most_serious_first_and_can_be_filtered(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()

    everything = findings_service.list_findings(db_session, scan, per_page=200)
    ranks = [findings_service.SEVERITIES.index(r.severity) for r in everything.rows]
    assert ranks == sorted(ranks) and everything.total == len(everything.rows) > 10

    high = findings_service.list_findings(db_session, scan, severity="high", per_page=200)
    assert high.rows and {r.severity for r in high.rows} == {"high"}
    one_rule = findings_service.list_findings(db_session, scan, rule_id="SPF_MISSING")
    assert [r.rule_id for r in one_rule.rows] == ["SPF_MISSING"]
    junk = findings_service.list_findings(db_session, scan, severity="catastrophic", per_page=200)
    assert junk.total == everything.total  # an unknown severity is not a filter


def test_listing_is_paged_in_sql(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    first = findings_service.list_findings(db_session, scan, per_page=5)
    second = findings_service.list_findings(db_session, scan, per_page=5, page=2)
    assert len(first.rows) == 5 and first.pages == -(-first.total // 5)
    assert not {r.id for r in first.rows} & {r.id for r in second.rows}
    assert findings_service.list_findings(db_session, scan, per_page=1000).per_page == 200


def test_the_breakdown_counts_by_status_and_severity(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    counted = findings_service.breakdown(db_session, scan)
    assert counted.by_severity("all") == summary.by_severity and counted.total() == summary.total
    assert counted.by_severity("open") == summary.by_severity  # nothing was decided
    assert counted.by_severity("accepted") == {} and counted.total("false_positive") == 0
    empty = new_scan(db_session, "empty.example")
    assert findings_service.breakdown(db_session, empty).total() == 0


def test_the_rules_that_fired_are_counted_most_serious_first(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    summary = findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    rules = findings_service.breakdown(db_session, scan).rules()

    assert sum(rule.count for rule in rules) == summary.total
    order = [findings_service.SEVERITIES.index(rule.severity) for rule in rules]
    assert order == sorted(order)  # most serious first
    spf = next(rule for rule in rules if rule.rule_id == "SPF_MISSING")
    assert (spf.title, spf.count) == ("No SPF record", 1)
    tls = next(rule for rule in rules if rule.rule_id == "TLS_INVALID")
    assert tls.severity == "high" and tls.count == 1  # the severity of its most serious finding
    assert findings_service.breakdown(db_session, new_scan(db_session, "e.example")).rules() == []


def test_a_rule_with_findings_of_several_severities_counts_once_at_its_highest(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    # the same rule, a second host, a lower severity: one line, the higher severity, two findings
    rows = [r for r in stored(db_session, scan) if r.rule_id == "TLS_INVALID"]
    twin = Finding(
        scan_id=scan.id, host_id=None, rule_id="TLS_INVALID", rule_version="1",
        subject="host:twin.example.com", severity="medium", confidence="high",
        attribution="hostname_supported", params={}, evidence=[], fingerprint="a" * 64,
    )  # fmt: skip
    db_session.add(twin)
    db_session.commit()
    line = next(
        rule
        for rule in findings_service.breakdown(db_session, scan).rules()
        if rule.rule_id == "TLS_INVALID"
    )
    assert (line.severity, line.count) == ("high", len(rows) + 1)


def test_the_page_of_a_host_has_its_own_findings_and_those_of_its_addresses(
    db_session: Session,
) -> None:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    scan.status = "completed"
    db_session.commit()

    found = findings_service.host_findings(db_session, scan, hosts["bad-tls.example.com"].id)
    assert found.state == "ready"
    own = {v.rule_id for v in found.own}
    assert own >= {"TLS_INVALID", "TLS_WEAK_KEY", "COOKIE_INSECURE"}
    assert found.own[0].severity == "high"  # most serious first
    assert all(v.scope == "host" for v in found.own)
    assert {v.rule_id for v in found.on_addresses} == {"RISKY_PORT_EXPOSED", "CVE_OBSERVED"}
    assert {v.address for v in found.on_addresses} == {"93.184.216.34"}

    quiet = findings_service.host_findings(db_session, scan, hosts["soon.example.com"].id)
    assert quiet.on_addresses == []  # it does not resolve to that address


def test_an_address_finding_reaches_every_host_that_resolves_to_it(db_session: Session) -> None:
    """The finding lists a few hosts only; every other host must find it on its page too."""
    scan, _ = populated_scan(db_session)
    twelve = [
        add_host(
            db_session,
            scan,
            f"extra{n:02d}.example.com",
            {"dns": CheckOutcome("ok", data={"addresses": ["93.184.216.34"], "blocked": []})},
        )
        for n in range(12)
    ]
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    scan.status = "completed"
    db_session.commit()
    risky = next(r for r in stored(db_session, scan) if r.rule_id == "RISKY_PORT_EXPOSED")
    assert not {str(h.id) for h in twelve} & set(risky.params["host_ids"])  # not listed in it

    for host in twelve:
        found = findings_service.host_findings(db_session, scan, host.id)
        assert "RISKY_PORT_EXPOSED" in {v.rule_id for v in found.on_addresses}
    cells = findings_service.host_summaries(db_session, scan, [h.id for h in twelve])
    assert set(cells) == {h.id for h in twelve}


def test_a_scan_without_findings_gives_a_page_that_says_why(db_session: Session) -> None:
    scan, hosts = populated_scan(db_session)
    assert findings_service.host_findings(db_session, scan, hosts["bad-tls.example.com"].id) == (
        findings_service.HostFindings("pending", [], [])
    )
    scan.status = "completed"
    assert findings_service.evaluation_state(scan) == "not_evaluated"
    scan.summary = {"findings": {"error": "evaluation_failed"}}
    assert findings_service.evaluation_state(scan) == "failed"
    scan.status = "cancelled"
    scan.summary = {}
    assert findings_service.evaluation_state(scan) == "not_evaluated"


def test_the_hosts_table_shows_the_count_and_the_worst_severity(db_session: Session) -> None:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    everyone = [h.id for h in hosts.values()]
    cells = findings_service.host_summaries(db_session, scan, everyone)

    bad = cells[hosts["bad-tls.example.com"].id]
    own = findings_service.host_findings
    scan.status = "completed"
    shown = own(db_session, scan, hosts["bad-tls.example.com"].id)
    assert bad.count == len(shown.own) + len(shown.on_addresses) and bad.top == "high"
    assert cells[hosts["soon.example.com"].id].top == "medium"  # a certificate that expires soon
    assert findings_service.host_summaries(db_session, scan, []) == {}
    assert (
        findings_service.host_summaries(db_session, new_scan(db_session, "x.example"), everyone)
        == {}
    )


def test_the_summary_adds_the_findings_up(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    scan.status = "completed"
    db_session.commit()

    summary = findings_service.findings_summary(db_session, scan)
    assert summary.state == "ready" and summary.total > 10
    assert sum(summary.by_severity.values()) == summary.total
    assert sum(rule.count for rule in summary.rules) == summary.total
    assert {rule.rule_id for rule in summary.rules} >= {"TLS_INVALID", "SPF_MISSING"}
    assert (summary.errors, summary.dropped) == ([], 0)

    scan.status = "running"
    pending = findings_service.findings_summary(db_session, scan)
    assert (pending.state, pending.total, pending.by_severity, pending.rules) == (
        "pending",
        0,
        {},
        [],
    )


def test_the_listing_is_filtered_but_its_summary_covers_the_whole_scan(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    scan.status = "completed"
    db_session.commit()

    everything = findings_service.findings_listing(db_session, scan, per_page=5)
    assert len(everything.items) == 5 and everything.page.total == everything.summary.total > 5
    filtered = findings_service.findings_listing(
        db_session, scan, severity="high", rule_id="TLS_INVALID"
    )
    assert [v.rule_id for v in filtered.items] == ["TLS_INVALID"]
    assert filtered.summary == everything.summary  # the filters are built from the whole scan

    scan.status = "running"
    unfinished = findings_service.findings_listing(db_session, scan)
    assert unfinished.summary.state == "pending" and unfinished.items == []


def test_the_summary_of_a_finished_scan_reports_rules_that_crashed_and_findings_dropped(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    scan.status = "completed"
    scan.summary = {"findings": {"total": 0, "errors": ["TLS_INVALID"], "dropped": 7}}
    summary = findings_service.findings_summary(db_session, scan)
    assert (summary.errors, summary.dropped, summary.total) == (["TLS_INVALID"], 7, 0)


# ----- describing


def test_a_finding_is_described_in_words_with_its_facts(db_session: Session) -> None:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    row = next(r for r in stored(db_session, scan) if r.rule_id == "TLS_INVALID")
    view = findings_service.describe(row, {hosts["bad-tls.example.com"].id: "bad-tls.example.com"})

    assert view.title == "Certificate not valid"
    assert (
        view.message
        == "The TLS certificate of bad-tls.example.com is not valid for clients: Expired."
    )
    assert ("Problems", "Expired") in view.facts and ("Days remaining", "-12") in view.facts
    assert view.hostname == "bad-tls.example.com" and view.advice
    assert (view.scope, view.address) == ("host", None)
    assert view.evidence == findings_service.EvidenceLink(row.host_id, "tls")


def test_the_evidence_of_each_kind_of_finding_is_found_where_it_is_shown(
    db_session: Session,
) -> None:
    scan, hosts = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()
    views = {
        v.rule_id: v
        for v in findings_service.describe_all(
            db_session, stored(db_session, scan), scan.assessment_id
        )
    }

    spf = views["SPF_MISSING"]
    assert (spf.scope, spf.evidence) == ("domain", findings_service.EvidenceLink(None, "email"))
    port = views["RISKY_PORT_EXPOSED"]
    assert (port.scope, port.address) == ("address", "93.184.216.34")
    assert port.evidence == findings_service.EvidenceLink(hosts["bad-tls.example.com"].id, "ports")
    assert ("Hosts on this address", "bad-tls.example.com") in port.facts


def test_hosts_beyond_those_listed_are_counted_in_the_facts(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    row = next(r for r in stored(db_session, scan) if r.rule_id == "RISKY_PORT_EXPOSED")
    row.params = {**row.params, "host_count": 9}
    view = findings_service.describe(row)
    assert ("Hosts on this address", "bad-tls.example.com and 8 more") in view.facts


def test_lists_and_codes_in_messages_are_rendered_readably() -> None:
    assert (
        findings_service.render_value("failures", ["expired", "hostname_mismatch"])
        == "Expired, Name mismatch"
    )
    assert findings_service.render_value("problems", ["multiple_records"]).startswith(
        "More than one record"
    )
    assert findings_service.render_value("x", ["a", "b"]) == "a, b"
    assert (
        findings_service.render_value("x", []) == "—"
        and findings_service.render_value("x", None) == "—"
    )
    assert (
        findings_service.render_value("x", True) == "Yes"
        and findings_service.render_value("x", 3) == "3"
    )
    assert findings_service.render_value("ending", "no all term") == "no all term"


def test_exploitation_data_is_rendered_as_words_and_percent() -> None:
    assert findings_service.render_value("max_epss", 0.97312) == "97.3 %"
    assert findings_service.render_value("max_epss", 0.99999) == "> 99.9 %"  # never 100 %
    assert findings_service.render_value("max_epss", None) == "—"
    assert findings_service.render_value("ranked_by", "kev_epss") == "CISA KEV and EPSS"
    assert "EPSS is not installed" in findings_service.render_value("ranked_by", "kev")
    assert "KEV catalogue is not installed" in findings_service.render_value("ranked_by", "epss")
    assert findings_service.render_value("ranked_by", "none").startswith("not ranked")
    assert findings_service.render_value("ranked_by", "anything else").startswith("not ranked")


def test_a_finding_of_a_rule_that_no_longer_exists_still_shows(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    ghost = Finding(
        id=uuid.uuid4(), scan_id=scan.id, host_id=None, rule_id="RETIRED_RULE", rule_version="1",
        subject="domain:example.com", severity="low", confidence="high", attribution="domain",
        params={}, evidence=[], fingerprint="f" * 64,
    )  # fmt: skip
    view = findings_service.describe(ghost)
    assert (view.title, view.message, view.facts) == ("RETIRED_RULE", "", [])


def test_a_message_whose_parameters_went_missing_falls_back_to_the_title(
    db_session: Session,
) -> None:
    scan, _ = populated_scan(db_session)
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    row = next(r for r in stored(db_session, scan) if r.rule_id == "TLS_INVALID")
    row.params = {}
    assert findings_service.describe(row).message == "Certificate not valid"


# ----- the command line


def test_the_findings_commands(db_session: Session, cli_runner: FlaskCliRunner) -> None:
    listed = cli_runner.invoke(args=["findings", "rules"])
    assert listed.exit_code == 0
    assert "TLS_INVALID" in listed.output and "LOCATION_OUTSIDE_EU_CH" in listed.output
    assert "rules, set" in listed.output

    scan, _ = populated_scan(db_session, "cli.example")
    scan.status, scan.finished_at = "completed", utc_now()
    db_session.commit()
    done = cli_runner.invoke(args=["findings", "evaluate", "--domain", "cli.example"])
    assert done.exit_code == 0 and "cli.example:" in done.output and "findings (" in done.output
    assert stored(db_session, scan)

    nothing = cli_runner.invoke(args=["findings", "evaluate", "--domain", "unknown.example"])
    assert "No finished scan to evaluate." in nothing.output


def test_a_takeover_finding_reads_as_a_sentence_with_its_facts(db_session: Session) -> None:
    from tests.checks.test_takeover_check import GITHUB_UNCLAIMED, HOST, Web, dns, html
    from tests.checks.test_takeover_check import run as run_takeover

    scan = new_scan(db_session, "vendor.example")
    previous = dns("vendor.github.io")
    unclaimed = run_takeover(Web({("http", HOST): html(404, GITHUB_UNCLAIMED)}), previous)
    add_host(db_session, scan, HOST, {"dns": previous, "takeover": unclaimed})
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()

    (row,) = [r for r in stored(db_session, scan) if r.rule_id == "TAKEOVER_LIKELY"]
    assert (row.severity, row.confidence) == ("high", "medium")  # GitHub checks something first
    view = findings_service.describe(row)
    assert view.title == "Alias may be taken over"
    assert view.message == (
        "shop.vendor.example is an alias for vendor.github.io at GitHub Pages, and the name "
        'behind it looks unclaimed: the service shows its "nothing here" page for the name.'
    )
    assert ("Service", "GitHub Pages") in view.facts and ("HTTP status", "404") in view.facts
    assert ("The page says", "There isn't a GitHub Pages site here.") in view.facts
    claim = ("Can a stranger claim the name?", "It depends on checks the service makes")
    assert claim in view.facts
    assert view.evidence == findings_service.EvidenceLink(row.host_id, "takeover")  # the details
    assert view.advice


def test_a_missing_name_that_anyone_can_register_replaces_the_dangling_alias_finding(
    db_session: Session,
) -> None:
    from tests.checks.test_takeover_check import HOST, Web, dns
    from tests.checks.test_takeover_check import run as run_takeover

    scan = new_scan(db_session, "vendor.example")
    previous = dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    outcome = run_takeover(Web(), previous)
    add_host(db_session, scan, HOST, {"dns": previous, "takeover": outcome})
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()

    assert {r.rule_id for r in stored(db_session, scan)} == {"TAKEOVER_LIKELY"}  # one problem
    (row,) = stored(db_session, scan)
    view = findings_service.describe(row)
    assert ("How it shows", "the name does not exist and anyone can register it") in view.facts
    assert ("Can a stranger claim the name?", "Yes, anyone can register it") in view.facts
    assert "HTTP status" not in {label for label, _ in view.facts}  # nothing was asked of the host


def test_protocol_findings_read_as_sentences_with_their_facts(db_session: Session) -> None:
    from app.checks.tls_protocols import outcome_from_protocols
    from tests.checks.test_tls_protocols_check import answers

    scan = new_scan(db_session, "vendor.example")
    risky = answers(
        {"TLSv1.2": "accepted", "TLSv1.3": "accepted", "TLSv1.1": "accepted"},
        {"anonymous_or_null": "accepted"},
        ciphers={"TLSv1.2": "AES256-GCM-SHA384", "anonymous_or_null": "NULL-SHA256"},
    )
    add_host(
        db_session, scan, "www.vendor.example", {"tls_protocols": outcome_from_protocols(risky)}
    )
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    db_session.commit()

    views = {row.rule_id: findings_service.describe(row) for row in stored(db_session, scan)}
    assert set(views) == {
        "TLS_LEGACY_PROTOCOL",
        "TLS_NULL_OR_ANONYMOUS_SUITES",
        "TLS_NO_FORWARD_SECRECY",
    }
    legacy = views["TLS_LEGACY_PROTOCOL"]
    assert legacy.message == (
        "www.vendor.example still accepts TLS 1.1 next to the current versions. TLS 1.0 and 1.1 "
        "were retired in 2021 (RFC 8996)."
    )
    assert ("Outdated versions accepted", "TLS 1.1") in legacy.facts
    assert ("Current versions accepted", "TLS 1.2, TLS 1.3") in legacy.facts
    assert legacy.evidence == findings_service.EvidenceLink(
        legacy.evidence.host_id, "tls_protocols"
    )
    assert ("Suite it chose", "NULL-SHA256") in views["TLS_NULL_OR_ANONYMOUS_SUITES"].facts
    assert views["TLS_NO_FORWARD_SECRECY"].message.startswith(
        "In a TLS 1.2 handshake www.vendor.example chose AES256-GCM-SHA384"
    )
