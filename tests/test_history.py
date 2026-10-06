"""The scans of an assessment over time, and what changed between two of them."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import Assessment, Finding, Scan, User
from app.service import decisions
from app.service import findings as findings_service
from app.service import history as history_service
from app.service import scans as scan_service
from tests.checks.test_ip_check import cloudflare
from tests.rules.helpers import expired, http_only, tls
from tests.rules.scenario import US, located
from tests.test_engine import CONFIG, new_scan
from tests.test_findings_service import RULES_CONFIG, add_host

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
D = ".example.com"


def finish(session: Session, scan: Scan, status: str = "completed", minutes: int = 0) -> None:
    started = NOW + timedelta(minutes=minutes)
    scan.status, scan.started_at, scan.finished_at = (
        status,
        started,
        started + timedelta(seconds=75),
    )
    session.commit()


def evaluate(session: Session, scan: Scan) -> None:
    findings_service.evaluate_scan(session, scan, RULES_CONFIG)
    session.commit()


def pairs(session: Session, scan: Scan) -> set[tuple[str, str]]:
    """(rule, subject) of every finding of the scan."""
    rows = session.scalars(select(Finding).where(Finding.scan_id == scan.id))
    return {(row.rule_id, row.subject) for row in rows}


def keys(views: object) -> set[tuple[str, str]]:
    return {(view.rule_id, view.subject) for view in views}  # type: ignore[attr-defined]


@dataclass
class Two:
    assessment: Assessment
    user: User
    older: Scan
    newer: Scan


def two_scans(session: Session) -> Two:
    """A scan and a re-scan of one domain that differ in every way a comparison tells apart.

    alpha: its certificate was expired, now it is fine          -> a resolved finding
    beta:  no HTTPS, then its web check fails                   -> not re-checked (check failed)
    gamma: a certificate about to expire, then the host is gone -> not re-checked (no such host)
    edge:  a CDN edge outside the area, then a plain address    -> severity changed (Medium to High)
    delta: new, with an expired certificate                     -> a new finding and a new host
    epsilon: expired in both                                    -> unchanged
    """
    older = new_scan(session)
    user = session.get(User, older.requested_by)
    assert user is not None
    add_host(session, older, f"alpha{D}", {"tls": expired()})
    add_host(session, older, f"beta{D}", {"http": http_only()})
    add_host(session, older, f"gamma{D}", {"tls": tls(days_until_expiration=5)})
    add_host(session, older, f"edge{D}", {"ip": located(cloudflare())})
    add_host(session, older, f"epsilon{D}", {"tls": expired()})
    evaluate(session, older)
    finish(session, older)

    newer = scan_service.start_scan(session, older.assessment, user, CONFIG)
    session.commit()
    add_host(session, newer, f"alpha{D}", {"tls": tls()})
    add_host(session, newer, f"beta{D}", {"http": CheckOutcome("error", "timeout")})
    add_host(session, newer, f"edge{D}", {"ip": located(US)})
    add_host(session, newer, f"delta{D}", {"tls": expired()})
    add_host(session, newer, f"epsilon{D}", {"tls": expired()})
    evaluate(session, newer)
    finish(session, newer, minutes=60)
    return Two(older.assessment, user, older, newer)


def compare(session: Session, two: Two) -> history_service.Comparison:
    return history_service.compare(session, two.assessment, two.older, two.newer, today=NOW.date())


# ------------------------------------------------------------------------------ the comparison


def test_what_changed_is_told_apart_by_what_was_checked_again(db_session: Session) -> None:
    two = two_scans(db_session)
    result = compare(db_session, two)

    assert result.findings_comparable and not result.rules_differ
    assert keys(result.new) == {("TLS_INVALID", f"host:delta{D}")}
    assert keys(result.resolved) == {("TLS_INVALID", f"host:alpha{D}")}
    assert [
        (c.finding.rule_id, c.finding.subject, c.was, c.finding.severity) for c in result.changed
    ] == [("LOCATION_OUTSIDE_EU_CH", f"host:edge{D}", "medium", "high")]
    assert result.unchanged == 1  # epsilon's expired certificate


def test_a_finding_whose_checks_did_not_answer_again_is_not_called_resolved(
    db_session: Session,
) -> None:
    result = compare(db_session, two_scans(db_session))
    gaps = {(u.finding.rule_id, u.finding.subject): u.gap for u in result.unclear}

    # beta is in the newer scan, but its web check failed: everything that rested on it (no HTTPS,
    # and the missing security headers of the plain page) cannot be judged
    beta = {key: gap for key, gap in gaps.items() if key[1] == f"host:beta{D}"}
    assert ("NO_HTTPS", f"host:beta{D}") in beta and len(beta) >= 2
    assert set(beta.values()) == {history_service.Gap("http", f"beta{D}", "error", "timeout")}
    # gamma is not in the newer scan at all
    assert {key: gap for key, gap in gaps.items() if key[1] == f"host:gamma{D}"} == {
        ("TLS_EXPIRES_SOON", f"host:gamma{D}"): history_service.Gap("tls", f"gamma{D}", None, None)
    }
    assert set(gaps) == set(beta) | {("TLS_EXPIRES_SOON", f"host:gamma{D}")}
    assert not keys(result.resolved) & set(gaps)


def test_hosts_are_matched_by_name(db_session: Session) -> None:
    result = compare(db_session, two_scans(db_session))
    assert [h.hostname for h in result.hosts_added] == [f"delta{D}"]
    assert [h.hostname for h in result.hosts_removed] == [f"gamma{D}"]
    assert (result.hosts_added_total, result.hosts_removed_total, result.hosts_kept) == (1, 1, 4)


def test_decisions_carry_over_and_are_counted_among_the_unchanged(db_session: Session) -> None:
    two = two_scans(db_session)
    epsilon = db_session.scalars(
        select(Finding).where(
            Finding.scan_id == two.newer.id, Finding.subject == f"host:epsilon{D}"
        )
    ).one()
    decisions.decide(
        db_session, two.assessment.id, epsilon, two.user,
        status="accepted", reason="Known.", today=NOW.date(),
    )  # fmt: skip
    db_session.commit()

    result = compare(db_session, two)
    assert (result.unchanged, result.unchanged_decided) == (1, 1)
    # a finding that was decided about shows its status wherever it is listed
    delta = db_session.scalars(
        select(Finding).where(Finding.scan_id == two.newer.id, Finding.subject == f"host:delta{D}")
    ).one()
    decisions.decide(
        db_session, two.assessment.id, delta, two.user,
        status="false_positive", reason="Test host.", today=NOW.date(),
    )  # fmt: skip
    db_session.commit()
    assert [v.status for v in compare(db_session, two).new] == ["false_positive"]


def test_the_lists_are_capped_but_the_counts_are_complete(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    two = two_scans(db_session)
    for name in ("one", "two", "three"):
        add_host(db_session, two.newer, f"{name}{D}", {"tls": expired()})
    evaluate(db_session, two.newer)
    monkeypatch.setattr(history_service, "MAX_LISTED", 2)

    result = compare(db_session, two)
    assert result.new_total == 4 and len(result.new) == 2
    assert result.hosts_added_total == 4 and len(result.hosts_added) == 2


# ------------------------------------------------------------------------------ what it cannot say


def test_findings_are_not_compared_when_a_scan_was_never_evaluated(db_session: Session) -> None:
    two = two_scans(db_session)
    two.older.summary = {}  # cancelled, or from before the rules existed
    db_session.commit()

    result = compare(db_session, two)
    assert result.findings_state == ("not_evaluated", "ready") and not result.findings_comparable
    assert not (result.new or result.resolved or result.changed or result.unclear)
    assert result.unchanged == 0
    assert result.hosts_added_total == 1  # the hosts can still be compared


def test_scans_judged_by_different_rules_say_so(db_session: Session) -> None:
    two = two_scans(db_session)
    two.newer.summary = {**(two.newer.summary or {}), "findings": {
        **findings_service.evaluation_info(two.newer), "ruleset": "another-rule-set",
    }}  # fmt: skip
    db_session.commit()
    assert compare(db_session, two).rules_differ


def test_findings_a_scan_could_not_keep_are_counted_so_that_the_page_can_say_so(
    db_session: Session,
) -> None:
    two = two_scans(db_session)
    assert compare(db_session, two).findings_dropped == (0, 0)
    two.newer.summary = {
        **(two.newer.summary or {}),
        "findings": {**findings_service.evaluation_info(two.newer), "dropped": 4},
    }
    db_session.commit()
    assert compare(db_session, two).findings_dropped == (0, 4)


def set_discovery(session: Session, scan: Scan, **data: object) -> None:
    row = scan_service.get_discovery(session, scan)
    assert row is not None
    row.status, row.data = "ok", data
    session.commit()


def test_a_missing_host_is_not_called_gone_when_discovery_was_incomplete(
    db_session: Session,
) -> None:
    two = two_scans(db_session)
    set_discovery(
        db_session,
        two.newer,
        sources=[
            {"source": "ctlogs", "status": "ok"},
            {"source": "crtsh", "status": "error", "reason_code": "http_404"},
            {"source": "certspotter", "status": "ok", "truncated": True},
        ],
        counts={"dropped_by_cap": 30},
        planned={"dropped_by_cap": 2},
    )
    set_discovery(db_session, two.older, sources=[{"source": "ctlogs", "status": "ok"}])

    result = compare(db_session, two)
    assert result.newer_gaps.sources == ("crt.sh", "CertSpotter")
    assert result.newer_gaps.over_limit == 32 and result.newer_gaps
    assert not result.older_gaps  # nothing to say about the older scan


# ------------------------------------------------------------------------------ the list


def test_the_history_lists_the_scans_newest_first_with_what_each_found(db_session: Session) -> None:
    two = two_scans(db_session)
    rows = history_service.list_scans(db_session, two.assessment.id)

    assert [row.scan.id for row in rows] == [two.newer.id, two.older.id]
    newer, older = rows
    assert newer.started_by == two.user.email and newer.hosts == 5 and older.hosts == 5
    assert newer.duration == timedelta(seconds=75)
    assert older.findings == len(pairs(db_session, two.older))
    assert older.serious == sum(  # the critical and high ones
        1 for f in db_session.scalars(select(Finding).where(Finding.scan_id == two.older.id))
        if f.severity in ("critical", "high")
    )  # fmt: skip
    assert newer.previous == two.older.id and older.previous is None


def test_a_scan_that_did_not_run_to_the_end_is_not_something_to_compare_with(
    db_session: Session,
) -> None:
    two = two_scans(db_session)
    cancelled = scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()
    finish(db_session, cancelled, "cancelled", minutes=120)
    third = scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()
    finish(db_session, third, "partial", minutes=180)

    rows = {row.scan.id: row for row in history_service.list_scans(db_session, two.assessment.id)}
    assert rows[cancelled.id].findings is None and rows[cancelled.id].previous is None
    assert rows[third.id].previous == two.newer.id  # it skips the cancelled scan
    assert scan_service.previous_scan_id(db_session, third) == two.newer.id
    assert scan_service.previous_scan_id(db_session, cancelled) is None
    assert scan_service.previous_scan_id(db_session, two.older) is None

    finished = history_service.finished_scans(db_session, two.assessment.id)
    assert [s.id for s in finished] == [third.id, cancelled.id, two.newer.id, two.older.id]
    assert history_service.default_pair(finished) == (two.newer, third)  # not the cancelled one


def test_a_scan_in_progress_has_no_report_and_no_findings_yet(db_session: Session) -> None:
    two = two_scans(db_session)
    running = scan_service.start_scan(db_session, two.assessment, two.user, CONFIG)
    db_session.commit()

    row = history_service.list_scans(db_session, two.assessment.id)[0]
    assert row.scan.id == running.id and row.findings is None and row.duration is None
    assert [s.id for s in history_service.finished_scans(db_session, two.assessment.id)] == [
        two.newer.id,
        two.older.id,
    ]  # only scans that ended can be compared


def test_there_is_nothing_to_compare_with_fewer_than_two_scans_that_ran_to_the_end(
    db_session: Session,
) -> None:
    only = new_scan(db_session)
    finish(db_session, only)
    assert (
        history_service.default_pair(history_service.finished_scans(db_session, only.assessment_id))
        is None
    )
    assert history_service.default_pair([]) is None


def test_two_scans_are_put_in_order_whichever_way_they_were_asked_for(db_session: Session) -> None:
    two = two_scans(db_session)
    assert history_service.in_order(two.newer, two.older) == (two.older, two.newer)
    assert history_service.in_order(two.older, two.newer) == (two.older, two.newer)


def test_a_scan_is_found_only_through_its_own_assessment(db_session: Session) -> None:
    two = two_scans(db_session)
    other = new_scan(db_session, "other.example")
    assert history_service.get_scan(db_session, two.assessment.id, two.older.id) == two.older
    assert history_service.get_scan(db_session, other.assessment_id, two.older.id) is None
