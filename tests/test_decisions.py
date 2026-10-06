"""What the team decided about findings: accepting, false positives, reopening, expiry."""

from __future__ import annotations

import logging
import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingDisposition, Scan, User
from app.models.base import utc_now
from app.service import decisions
from app.service.decisions import DecisionError
from tests.helpers import audit_rows, create_user
from tests.test_summary import evaluated

TODAY = date(2026, 10, 5)
SPF = "SPF_MISSING:domain:example.com"
TLS = "TLS_INVALID:host:bad-tls.example.com"


def user_of(session: Session, scan: Scan) -> User:
    user = session.get(User, scan.requested_by)
    assert user is not None
    return user


def row_for(session: Session, scan: Scan, finding: Finding) -> FindingDisposition | None:
    return session.scalar(
        select(FindingDisposition).where(
            FindingDisposition.assessment_id == scan.assessment_id,
            FindingDisposition.fingerprint == finding.fingerprint,
        )
    )


# ----- accepting


def test_accepting_a_finding_records_who_why_and_until_when(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    before = utc_now()

    row = decisions.decide(
        db_session, scan.assessment_id, rows[SPF], person,
        status="accepted", reason="  The vendor sends no mail from this domain.  ",
        review_by="2027-01-31", today=TODAY,
    )  # fmt: skip
    db_session.commit()

    assert (row.status, row.reason) == ("accepted", "The vendor sends no mail from this domain.")
    assert (row.decided_by, row.review_by, row.history) == (person.id, date(2027, 1, 31), [])
    assert before <= row.decided_at <= utc_now()
    assert (row.assessment_id, row.fingerprint) == (scan.assessment_id, rows[SPF].fingerprint)
    assert decisions.status_of(row, TODAY) == "accepted"


def test_a_false_positive_takes_no_review_date(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    row = decisions.decide(
        db_session, scan.assessment_id, rows[TLS], user_of(db_session, scan),
        status="false_positive", reason="That host is a test fixture.",
        review_by="2027-01-31", today=TODAY,
    )  # fmt: skip
    assert (row.status, row.review_by) == (
        "false_positive",
        None,
    )  # the date is ignored, not stored
    assert decisions.status_of(row, TODAY) == "false_positive"


def test_a_decision_needs_a_reason_and_a_known_kind(db_session: Session) -> None:
    scan, rows = evaluated(db_session)

    def attempt(**fields: str) -> None:
        values = {"status": "accepted", "reason": "ok", **fields}
        decisions.decide(
            db_session,
            scan.assessment_id,
            rows[SPF],
            user_of(db_session, scan),
            today=TODAY,
            **values,
        )

    for reason in ("", "   ", "\n\t"):
        with pytest.raises(DecisionError, match="reason"):
            attempt(reason=reason)
    with pytest.raises(DecisionError, match="too long"):
        attempt(reason="x" * (decisions.MAX_REASON + 1))
    attempt(reason="x" * decisions.MAX_REASON)  # exactly the limit is fine
    for status in ("", "open", "banana", "ACCEPTED"):
        with pytest.raises(DecisionError, match="Choose a decision"):
            attempt(status=status)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("tomorrow", "not a valid date"),
        ("2026-13-01", "not a valid date"),
        ("05.10.2027", "not a valid date"),
        ("2026-10-05", "after today"),  # today is not "later"
        ("2026-10-04", "after today"),
        ("2000-01-01", "after today"),
        ("2036-10-05", "within the next five years"),
    ],
)
def test_review_dates_are_checked(text: str, message: str) -> None:
    with pytest.raises(DecisionError, match=message):
        decisions.parse_review_by(text, TODAY)


def test_good_review_dates_and_none_at_all() -> None:
    assert (
        decisions.parse_review_by("", TODAY) is None
        and decisions.parse_review_by("  ", TODAY) is None
    )
    assert decisions.parse_review_by("2026-10-06", TODAY) == date(2026, 10, 6)  # tomorrow
    assert decisions.parse_review_by(" 2027-10-05 ", TODAY) == date(2027, 10, 5)
    last = TODAY + timedelta(days=decisions.MAX_REVIEW_DAYS)
    assert decisions.parse_review_by(last.isoformat(), TODAY) == last


def test_the_review_window_is_what_the_date_input_may_choose() -> None:
    earliest, latest = decisions.review_window(TODAY)
    assert earliest == "2026-10-06"
    assert date.fromisoformat(latest) == TODAY + timedelta(days=decisions.MAX_REVIEW_DAYS)
    assert decisions.parse_review_by(earliest, TODAY) and decisions.parse_review_by(latest, TODAY)


# ----- changing and reopening


def test_deciding_again_replaces_the_decision_and_keeps_the_old_one_in_the_history(
    db_session: Session,
) -> None:
    scan, rows = evaluated(db_session)
    first, second = user_of(db_session, scan), create_user(db_session)
    decisions.decide(
        db_session, scan.assessment_id, rows[SPF], first,
        status="accepted", reason="Known.", review_by="2027-01-31", today=TODAY,
    )  # fmt: skip
    db_session.commit()
    earlier = row_for(db_session, scan, rows[SPF])
    assert earlier is not None
    decided_at = earlier.decided_at

    decisions.decide(
        db_session, scan.assessment_id, rows[SPF], second,
        status="false_positive", reason="It is not a mail domain at all.", today=TODAY,
    )  # fmt: skip
    db_session.commit()

    rows_now = db_session.scalars(
        select(FindingDisposition).where(FindingDisposition.fingerprint == rows[SPF].fingerprint)
    ).all()
    assert len(rows_now) == 1  # replaced, not added
    now = rows_now[0]
    assert (now.status, now.reason, now.decided_by, now.review_by) == (
        "false_positive", "It is not a mail domain at all.", second.id, None,
    )  # fmt: skip
    assert now.decided_at >= decided_at
    (kept,) = now.history
    assert kept["status"] == "accepted" and kept["reason"] == "Known."
    assert kept["decided_by"] == str(first.id) and kept["review_by"] == "2027-01-31"
    assert kept["decided_at"] and kept["replaced_at"]


def test_the_history_keeps_the_last_states_only(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    for n in range(decisions.MAX_HISTORY + 5):
        decisions.decide(
            db_session, scan.assessment_id, rows[SPF], person,
            status="accepted", reason=f"version {n}", today=TODAY,
        )  # fmt: skip
        db_session.flush()
    row = row_for(db_session, scan, rows[SPF])
    assert row is not None and len(row.history) == decisions.MAX_HISTORY
    assert row.reason == f"version {decisions.MAX_HISTORY + 4}"
    assert row.history[-1]["reason"] == f"version {decisions.MAX_HISTORY + 3}"  # the one before


def test_reopening_takes_the_decision_back(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    decisions.decide(
        db_session,
        scan.assessment_id,
        rows[SPF],
        person,
        status="accepted",
        reason="Known.",
        today=TODAY,
    )
    db_session.commit()

    assert decisions.reopen(db_session, scan.assessment_id, rows[SPF], person) is True
    db_session.commit()
    assert row_for(db_session, scan, rows[SPF]) is None
    assert decisions.status_of(row_for(db_session, scan, rows[SPF]), TODAY) == "open"
    assert (
        decisions.reopen(db_session, scan.assessment_id, rows[SPF], person) is False
    )  # nothing left


# ----- expiry


def test_an_acceptance_whose_review_date_has_passed_is_open_again_and_flagged(
    db_session: Session,
) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    decisions.decide(
        db_session, scan.assessment_id, rows[SPF], person,
        status="accepted", reason="For now.", review_by="2026-11-01", today=TODAY,
    )  # fmt: skip
    db_session.commit()
    row = row_for(db_session, scan, rows[SPF])
    assert row is not None
    fingerprints = {rows[SPF].fingerprint}

    on_the_day = date(2026, 11, 1)  # still valid on the review date itself
    assert decisions.status_of(row, on_the_day) == "accepted" and not decisions.has_lapsed(
        row, on_the_day
    )
    after = date(2026, 11, 2)
    assert decisions.status_of(row, after) == "open" and decisions.has_lapsed(row, after)

    kept = decisions.load_decisions(db_session, scan.assessment_id, fingerprints, after)
    decision = kept[rows[SPF].fingerprint]
    assert (decision.status, decision.lapsed, decision.reason) == ("accepted", True, "For now.")
    valid = decisions.load_decisions(db_session, scan.assessment_id, fingerprints, on_the_day)
    assert valid[rows[SPF].fingerprint].lapsed is False

    # accepting it again after it lapsed is an ordinary change of the decision
    decisions.decide(
        db_session, scan.assessment_id, rows[SPF], person,
        status="accepted", reason="Still fine.", review_by="2027-05-01", today=after,
    )  # fmt: skip
    db_session.flush()
    assert decisions.status_of(row, after) == "accepted" and len(row.history) == 1


def test_a_false_positive_never_lapses(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    decisions.decide(
        db_session, scan.assessment_id, rows[TLS], user_of(db_session, scan),
        status="false_positive", reason="Test fixture.", today=TODAY,
    )  # fmt: skip
    row = row_for(db_session, scan, rows[TLS])
    assert row is not None and decisions.status_of(row, date(2099, 1, 1)) == "false_positive"


# ----- scope


def test_decisions_are_read_by_fingerprint_for_one_assessment(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    other, other_rows = evaluated(db_session)  # the same facts in another assessment
    decisions.decide(
        db_session, scan.assessment_id, rows[SPF], user_of(db_session, scan),
        status="accepted", reason="Known.", today=TODAY,
    )  # fmt: skip
    db_session.commit()
    both = {rows[SPF].fingerprint, rows[TLS].fingerprint}

    mine = decisions.load_decisions(db_session, scan.assessment_id, both, TODAY)
    assert set(mine) == {rows[SPF].fingerprint}
    assert mine[rows[SPF].fingerprint].decided_by == user_of(db_session, scan).email
    assert decisions.load_decisions(db_session, other.assessment_id, both, TODAY) == {}
    assert decisions.load_decisions(db_session, scan.assessment_id, set(), TODAY) == {}
    assert other_rows[SPF].fingerprint == rows[SPF].fingerprint  # same finding, other assessment


def test_a_finding_is_found_only_through_its_own_assessment(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    other, _ = evaluated(db_session)
    found = decisions.get_finding(db_session, scan.assessment_id, rows[SPF].id)
    assert found is not None and found.id == rows[SPF].id
    assert decisions.get_finding(db_session, other.assessment_id, rows[SPF].id) is None
    assert decisions.get_finding(db_session, scan.assessment_id, uuid.uuid4()) is None


def test_losing_the_race_to_decide_is_reported_not_crashed(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    decisions.decide(
        db_session,
        scan.assessment_id,
        rows[SPF],
        person,
        status="accepted",
        reason="First.",
        today=TODAY,
    )
    db_session.flush()
    with pytest.raises(DecisionError, match="Somebody else decided"):
        decisions._create(  # the second insert of the same finding, as a parallel request makes it
            db_session, scan.assessment_id, rows[SPF].fingerprint, status="accepted",
            reason="Second.", user=person, at=utc_now(), review_by=None,
        )  # fmt: skip
    # the savepoint took the failure; the session still works
    assert db_session.scalar(select(FindingDisposition.reason)) == "First."


# ----- the trail


def test_every_change_is_in_the_audit_log_without_the_reason(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    scan, rows = evaluated(db_session)
    person = user_of(db_session, scan)
    secret = "the-customer-asked-us-not-to-write-this-down"
    with caplog.at_level(logging.INFO, logger="app.audit"):
        decisions.decide(
            db_session, scan.assessment_id, rows[SPF], person,
            status="accepted", reason=secret, review_by="2027-01-31", today=TODAY,
        )  # fmt: skip
        db_session.flush()
        decisions.decide(
            db_session, scan.assessment_id, rows[SPF], person,
            status="false_positive", reason="Changed my mind.", today=TODAY,
        )  # fmt: skip
        decisions.reopen(db_session, scan.assessment_id, rows[SPF], person)

    entries = audit_rows(
        db_session, "finding.accepted", "finding.false_positive", "finding.reopened"
    )
    assert [e.action for e in entries] == [
        "finding.accepted",
        "finding.false_positive",
        "finding.reopened",
    ]
    first, second, third = entries
    assert first.actor_id == person.id and first.actor_email == person.email
    assert first.assessment_id == scan.assessment_id and first.subject == rows[SPF].fingerprint
    assert first.details == {
        "rule": "SPF_MISSING",
        "review_by": "2027-01-31",
        "domain": "example.com",
    }  # the first decision replaced nothing
    assert second.details["replaced"] == "accepted"  # the second took the first one's place
    assert third.details["was"] == "false_positive"
    assert third.details["decided_by"] == person.email  # who decided, as the row is deleted

    everything = repr([(e.subject, e.details) for e in entries]) + caplog.text
    assert secret not in everything and "Changed my mind" not in everything  # reasons stay out
