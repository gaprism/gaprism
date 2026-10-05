"""Findings read with their status: lists, counts, host views, descriptions."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import Finding, Host, Scan
from app.models.base import utc_now
from app.service import decisions
from app.service import findings as findings_service
from tests.test_decisions import SPF, TLS, user_of
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan
from tests.test_summary import evaluated

TODAY = utc_now().date()
DMARC = "DMARC_MISSING:domain:example.com"


def decide(
    session: Session,
    scan: Scan,
    finding: Finding,
    status: str,
    review_by: date | None = None,
    reason: str = "because",
) -> None:
    decisions.decide(
        session,
        scan.assessment_id,
        finding,
        user_of(session, scan),
        status=status,
        reason=reason,
        review_by=review_by.isoformat() if review_by else "",
        today=TODAY,
    )
    session.commit()


def decided(session: Session) -> tuple[Scan, dict[str, Finding]]:
    """A finished scan with one accepted, one false-positive and one lapsed finding."""
    scan, rows = evaluated(session)
    decide(session, scan, rows[SPF], "accepted", TODAY + timedelta(days=30))
    decide(session, scan, rows[TLS], "false_positive")
    decide(session, scan, rows[DMARC], "accepted", TODAY + timedelta(days=1))
    return scan, rows


# ----- lists


def test_each_status_lists_its_own_findings(db_session: Session) -> None:
    scan, rows = decided(db_session)
    listed = {
        status: {
            f.id
            for f in findings_service.list_findings(
                db_session, scan, status=status, per_page=200
            ).rows
        }
        for status in ("open", "accepted", "false_positive", "all")
    }
    assert listed["accepted"] == {rows[SPF].id, rows[DMARC].id}
    assert listed["false_positive"] == {rows[TLS].id}
    assert listed["open"] | listed["accepted"] | listed["false_positive"] == listed["all"]
    assert not listed["open"] & (listed["accepted"] | listed["false_positive"])
    assert len(listed["all"]) == len({f.id for f in rows.values()})


def test_a_lapsed_acceptance_is_listed_as_open(db_session: Session) -> None:
    scan, rows = decided(db_session)
    later = TODAY + timedelta(days=2)  # the review date of DMARC_MISSING has passed
    accepted = findings_service.list_findings(
        db_session, scan, status="accepted", today=later, per_page=200
    )
    opened = findings_service.list_findings(
        db_session, scan, status="open", today=later, per_page=200
    )
    assert rows[DMARC].id not in {f.id for f in accepted.rows}
    assert rows[DMARC].id in {f.id for f in opened.rows}
    assert rows[SPF].id in {f.id for f in accepted.rows}  # its date is further away


def test_in_the_full_list_the_open_findings_come_first(db_session: Session) -> None:
    scan, rows = decided(db_session)
    everything = findings_service.list_findings(db_session, scan, status="all", per_page=200).rows
    statuses = [
        "open"
        if f.fingerprint
        not in {rows[SPF].fingerprint, rows[TLS].fingerprint, rows[DMARC].fingerprint}
        else "decided"
        for f in everything
    ]
    assert statuses == sorted(
        statuses, key=lambda s: s != "open"
    )  # no open one after a decided one
    open_only = [f for f, s in zip(everything, statuses, strict=True) if s == "open"]
    ranks = [findings_service.SEVERITIES.index(f.severity) for f in open_only]
    assert ranks == sorted(ranks)  # and still most serious first among them


def test_filters_combine_with_the_status(db_session: Session) -> None:
    scan, rows = decided(db_session)
    high_open = findings_service.list_findings(
        db_session, scan, status="open", severity="high", per_page=200
    )
    assert rows[TLS].id not in {f.id for f in high_open.rows}  # decided, so not among the open ones
    assert {f.severity for f in high_open.rows} == {"high"}
    one = findings_service.list_findings(db_session, scan, status="accepted", rule_id="SPF_MISSING")
    assert [f.id for f in one.rows] == [rows[SPF].id]
    assert (
        findings_service.list_findings(
            db_session, scan, status="accepted", rule_id="TLS_INVALID"
        ).total
        == 0
    )
    junk = findings_service.list_findings(db_session, scan, status="nonsense", per_page=200)
    assert (
        junk.total
        == findings_service.list_findings(db_session, scan, status="all", per_page=200).total
    )


def test_paging_by_status_neither_repeats_nor_skips(db_session: Session) -> None:
    scan, _ = decided(db_session)
    seen: list[object] = []
    page = 1
    while True:
        chunk = findings_service.list_findings(
            db_session, scan, status="all", per_page=7, page=page
        )
        seen += [f.id for f in chunk.rows]
        if page >= chunk.pages:
            break
        page += 1
    assert len(seen) == len(set(seen)) == chunk.total


def test_the_findings_of_one_host_include_those_on_its_addresses(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    host = db_session.query(Host).filter_by(scan_id=scan.id, hostname="bad-tls.example.com").one()
    findings_service.evaluate_scan(db_session, scan, RULES_CONFIG)
    scan.status = "completed"
    db_session.commit()
    about = findings_service.list_findings(db_session, scan, host_id=host.id, per_page=200)
    rules = {f.rule_id for f in about.rows}
    assert {"TLS_INVALID", "COOKIE_INSECURE"} <= rules  # its own
    assert {"RISKY_PORT_EXPOSED", "CVE_OBSERVED"} <= rules  # about the address it resolves to
    assert all(f.host_id in (host.id, None) for f in about.rows)  # nobody else's findings
    elsewhere = db_session.query(Host).filter_by(scan_id=scan.id, hostname="soon.example.com").one()
    assert "RISKY_PORT_EXPOSED" not in {
        f.rule_id
        for f in findings_service.list_findings(
            db_session, scan, host_id=elsewhere.id, per_page=200
        ).rows
    }


# ----- counts


def test_the_breakdown_separates_open_accepted_and_false_positive(db_session: Session) -> None:
    scan, rows = decided(db_session)
    counted = findings_service.breakdown(db_session, scan)
    everything = len(rows)
    assert counted.total("accepted") == 2 and counted.total("false_positive") == 1
    assert counted.total("open") == everything - 3 and counted.total("all") == everything
    assert counted.by_severity("false_positive") == {"high": 1}
    assert "TLS_INVALID" not in {r.rule_id for r in counted.rules("open")}
    assert {r.rule_id for r in counted.rules("all")} >= {"TLS_INVALID", "SPF_MISSING"}
    assert counted.total("nonsense") == 0 and counted.by_severity("nonsense") == {}


def test_the_summary_counts_open_findings_and_names_the_decided_ones(db_session: Session) -> None:
    scan, _ = decided(db_session)
    summary = findings_service.findings_summary(db_session, scan)
    assert summary.total == summary.open_total + 3
    assert (summary.accepted, summary.false_positive) == (2, 1)
    assert sum(summary.by_severity.values()) == summary.open_total
    assert sum(rule.count for rule in summary.rules) == summary.open_total


def test_the_hosts_table_counts_open_findings_only(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    host = db_session.query(Host).filter_by(scan_id=scan.id, hostname="bad-tls.example.com").one()
    before = findings_service.host_summaries(db_session, scan, [host.id])[host.id]
    assert before.top == "high"

    decide(db_session, scan, rows[TLS], "false_positive")  # one of several High findings
    after = findings_service.host_summaries(db_session, scan, [host.id])[host.id]
    assert (after.count, after.top) == (before.count - 1, "high")

    # decide about every High finding of this host, its own and those on its address
    open_high = findings_service.list_findings(
        db_session, scan, host_id=host.id, severity="high", status="open", per_page=200
    )
    assert len(open_high.rows) >= 3
    for finding in open_high.rows:
        decide(db_session, scan, finding, "accepted")
    last = findings_service.host_summaries(db_session, scan, [host.id])[host.id]
    assert last.top == "medium" and last.count < after.count


# ----- views


def test_a_finding_carries_its_status_and_the_decision_behind_it(db_session: Session) -> None:
    scan, rows = decided(db_session)
    described = findings_service.describe_all(db_session, list(rows.values()), scan.assessment_id)
    views = {v.id: v for v in described}
    spf, tls = views[rows[SPF].id], views[rows[TLS].id]

    assert spf.status == "accepted" and spf.decision is not None
    assert (spf.decision.reason, spf.decision.lapsed) == ("because", False)
    assert spf.decision.decided_by == user_of(db_session, scan).email
    assert spf.decision.review_by == TODAY + timedelta(days=30)
    assert tls.status == "false_positive" and tls.decision is not None
    undecided = [v for v in views.values() if v.decision is None]
    assert undecided and all(v.status == "open" for v in undecided)


def test_a_lapsed_acceptance_is_an_open_finding_that_remembers_the_decision(
    db_session: Session,
) -> None:
    scan, rows = decided(db_session)
    later = TODAY + timedelta(days=2)
    (view,) = findings_service.describe_all(
        db_session, [rows[DMARC]], scan.assessment_id, today=later
    )
    assert view.status == "open"  # counted as open...
    assert view.decision is not None and view.decision.lapsed  # ...and flagged
    assert view.decision.status == "accepted"


def test_the_page_of_a_host_lists_open_findings_before_decided_ones(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    host = db_session.query(Host).filter_by(scan_id=scan.id, hostname="bad-tls.example.com").one()
    decide(db_session, scan, rows[TLS], "accepted")  # the most serious one of this host
    found = findings_service.host_findings(db_session, scan, host.id)
    statuses = [v.status for v in found.own]
    assert statuses[-1] == "accepted" and statuses.count("accepted") == 1
    assert statuses == sorted(statuses, key=lambda s: s != "open")
    assert found.own[0].status == "open"


def test_the_listing_defaults_to_open_and_offers_the_hosts(db_session: Session) -> None:
    scan, rows = decided(db_session)
    add_host(
        db_session,
        scan,
        "aaa-first.example.com",
        {"dns": CheckOutcome("ok", data={"addresses": []})},
    )
    listing = findings_service.findings_listing(db_session, scan)
    assert {v.status for v in listing.items} == {"open"}
    assert rows[SPF].id not in {v.id for v in listing.items}
    names = [name for _, name in listing.hosts]
    assert names == sorted(names) and names[0] == "aaa-first.example.com"
    accepted = findings_service.findings_listing(db_session, scan, status="accepted")
    assert {v.status for v in accepted.items} == {"accepted"} and accepted.page.total == 2


def test_the_host_filter_is_bounded(db_session: Session, monkeypatch: object) -> None:
    import pytest

    assert isinstance(monkeypatch, pytest.MonkeyPatch)
    scan, _ = populated_scan(db_session)
    monkeypatch.setattr(findings_service, "MAX_HOST_OPTIONS", 2)
    assert len(findings_service.host_options(db_session, scan)) == 2
