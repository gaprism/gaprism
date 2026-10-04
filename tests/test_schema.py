"""Database constraints the scan engine relies on (idempotent results, cascading deletes)."""

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    Assessment,
    CheckResult,
    Finding,
    FindingDisposition,
    Host,
    Scan,
    User,
)


def _make_scan(session: Session) -> tuple[Assessment, Scan, User]:
    user = User(email=f"{uuid.uuid4().hex[:10]}@example.org", password="x" * 20)
    session.add(user)
    session.flush()
    assessment = Assessment(domain="example.com", domain_display="example.com", created_by=user.id)
    session.add(assessment)
    session.flush()
    scan = Scan(assessment_id=assessment.id, requested_by=user.id)
    session.add(scan)
    session.flush()
    return assessment, scan, user


def _make_host(session: Session, scan: Scan, hostname: str = "www.example.com") -> Host:
    host = Host(scan_id=scan.id, hostname=hostname)
    session.add(host)
    session.flush()
    return host


def test_domain_level_check_exists_once_per_scan(db_session: Session) -> None:
    """NULL host_id rows are still unique per (scan, check): a retry cannot add a duplicate."""
    _, scan, _ = _make_scan(db_session)
    db_session.add(CheckResult(scan_id=scan.id, check_key="email_security"))
    db_session.flush()

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(CheckResult(scan_id=scan.id, check_key="email_security"))
        db_session.flush()

    db_session.add(CheckResult(scan_id=scan.id, check_key="rdap"))  # another check is fine
    db_session.flush()


def test_host_check_exists_once_per_host(db_session: Session) -> None:
    """The same check may run for different hosts, and for the domain, but once for each."""
    _, scan, _ = _make_scan(db_session)
    first = _make_host(db_session, scan, "a.example.com")
    second = _make_host(db_session, scan, "b.example.com")
    db_session.add_all(
        [
            CheckResult(scan_id=scan.id, host_id=first.id, check_key="tls"),
            CheckResult(scan_id=scan.id, host_id=second.id, check_key="tls"),
            CheckResult(scan_id=scan.id, host_id=None, check_key="tls"),
        ]
    )
    db_session.flush()

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(CheckResult(scan_id=scan.id, host_id=first.id, check_key="tls"))
        db_session.flush()


def test_hostname_is_unique_within_a_scan(db_session: Session) -> None:
    _, scan, _ = _make_scan(db_session)
    _make_host(db_session, scan)
    with pytest.raises(IntegrityError), db_session.begin_nested():
        _make_host(db_session, scan)


@pytest.mark.parametrize(
    "bad",
    [
        CheckResult(check_key="tls", status="clean"),  # not an outcome we model
        Finding(
            rule_id="X",
            subject="s",
            severity="urgent",
            confidence="high",
            attribution="domain",
            fingerprint="f",
        ),
        Finding(
            rule_id="X",
            subject="s",
            severity="low",
            confidence="high",
            attribution="guess",
            fingerprint="f",
        ),
    ],
    ids=["check-status", "finding-severity", "finding-attribution"],
)
def test_enumerated_values_are_enforced(db_session: Session, bad: CheckResult | Finding) -> None:
    _, scan, _ = _make_scan(db_session)
    bad.scan_id = scan.id
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(bad)
        db_session.flush()


def test_decision_is_unique_per_assessment_and_finding(db_session: Session) -> None:
    assessment, _, user = _make_scan(db_session)

    def decision() -> FindingDisposition:
        return FindingDisposition(
            assessment_id=assessment.id,
            fingerprint="a" * 64,
            status="accepted",
            reason="Reviewed with the vendor.",
            decided_by=user.id,
        )

    db_session.add(decision())
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(decision())
        db_session.flush()


def test_deleting_an_assessment_removes_everything_below_it(db_session: Session) -> None:
    assessment, scan, user = _make_scan(db_session)
    host = _make_host(db_session, scan)
    db_session.add_all(
        [
            CheckResult(scan_id=scan.id, host_id=host.id, check_key="tls"),
            Finding(
                scan_id=scan.id,
                host_id=host.id,
                rule_id="TLS_INVALID",
                subject="host:www.example.com",
                severity="high",
                confidence="high",
                attribution="hostname_supported",
                fingerprint="b" * 64,
            ),
            FindingDisposition(
                assessment_id=assessment.id,
                fingerprint="b" * 64,
                status="accepted",
                reason="Known issue.",
                decided_by=user.id,
            ),
        ]
    )
    db_session.flush()

    db_session.delete(assessment)
    db_session.flush()
    db_session.expire_all()

    for model in (Scan, Host, CheckResult, Finding, FindingDisposition):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0, model.__name__
