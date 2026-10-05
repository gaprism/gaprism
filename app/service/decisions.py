"""What people decided about findings: accepted, a false positive, or open again.

A decision belongs to the *assessment* and is keyed by the finding's fingerprint (rule and subject),
so it carries over to every re-scan; it never changes the evidence. The status of a finding is the
decision stored for its fingerprint, with one rule: an acceptance whose review date has passed no
longer applies, the finding is open again and is flagged "acceptance expired".

Reopening deletes the decision; before any change the previous state is appended to ``history``
(the last ``MAX_HISTORY`` states). Until the audit log (S3.5) exists every change is also logged,
without the reason text.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, case, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import AUDIT_LOGGER
from app.i18n import gettext as _
from app.models import Finding, FindingDisposition, Scan, User
from app.models.base import utc_now

log = logging.getLogger(AUDIT_LOGGER)

OPEN = "open"
ACCEPTED = "accepted"
FALSE_POSITIVE = "false_positive"
DECISIONS = (ACCEPTED, FALSE_POSITIVE)
STATUS_FILTERS = (OPEN, ACCEPTED, FALSE_POSITIVE, "all")  # what the findings page can show

MAX_REASON = 2000
MAX_REVIEW_DAYS = 5 * 366  # an acceptance should be looked at again within five years
MAX_HISTORY = 20


class DecisionError(Exception):
    """A decision that cannot be recorded. The message says why, in the reader's language."""


# --------------------------------------------------------------------------- status


def current_status(today: date) -> Any:
    """SQL: the status of a finding. An acceptance whose review date has passed no longer applies:
    the finding is open again."""
    lapsed = and_(
        FindingDisposition.status == ACCEPTED,
        FindingDisposition.review_by.is_not(None),
        FindingDisposition.review_by < today,
    )
    return case(
        (FindingDisposition.id.is_(None), OPEN),
        (lapsed, OPEN),
        else_=FindingDisposition.status,
    )


def with_decisions(query: Select[Any], assessment_id: uuid.UUID) -> Select[Any]:
    """Add the decision about each finding (an outer join: at most one per assessment and
    fingerprint). ``current_status`` then tells what the finding is."""
    return query.outerjoin(
        FindingDisposition,
        and_(
            FindingDisposition.assessment_id == assessment_id,
            FindingDisposition.fingerprint == Finding.fingerprint,
        ),
    )


def has_lapsed(row: FindingDisposition, today: date) -> bool:
    """An acceptance whose review date is behind us."""
    return row.status == ACCEPTED and row.review_by is not None and row.review_by < today


def status_of(row: FindingDisposition | None, today: date) -> str:
    """The status of a finding given the decision about it (``current_status`` in Python)."""
    if row is None or has_lapsed(row, today):
        return OPEN
    return row.status


@dataclass(frozen=True)
class Decision:
    """A decision as the pages show it."""

    status: str  # accepted | false_positive: what was decided (a lapsed acceptance stays accepted)
    reason: str
    decided_by: str  # the e-mail address of the person
    decided_at: datetime
    review_by: date | None
    lapsed: bool  # the review date has passed: the finding is open again


def load_decisions(
    session: Session, assessment_id: uuid.UUID, fingerprints: set[str], today: date
) -> dict[str, Decision]:
    """The decisions about these fingerprints, keyed by fingerprint (one query)."""
    if not fingerprints:
        return {}
    rows = session.execute(
        select(FindingDisposition, User.email)
        .join(User, User.id == FindingDisposition.decided_by)
        .where(
            FindingDisposition.assessment_id == assessment_id,
            FindingDisposition.fingerprint.in_(fingerprints),
        )
    )
    return {
        row.fingerprint: Decision(
            status=row.status,
            reason=row.reason,
            decided_by=email,
            decided_at=row.decided_at,
            review_by=row.review_by,
            lapsed=has_lapsed(row, today),
        )
        for row, email in rows
    }


def review_window(today: date | None = None) -> tuple[str, str]:
    """The first and the last day a review date may take, as ISO dates (for the date input)."""
    day = today or utc_now().date()
    return (day + timedelta(days=1)).isoformat(), (
        day + timedelta(days=MAX_REVIEW_DAYS)
    ).isoformat()


# --------------------------------------------------------------------------- deciding


def get_finding(
    session: Session, assessment_id: uuid.UUID, finding_id: uuid.UUID
) -> Finding | None:
    """A finding of any scan of the assessment (``None`` for one of another assessment)."""
    return session.scalar(
        select(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Finding.id == finding_id, Scan.assessment_id == assessment_id)
    )


def parse_review_by(text: str, today: date) -> date | None:
    """The review date from a form: empty is none, otherwise a day after today within five years."""
    text = text.strip()
    if not text:
        return None
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise DecisionError(_("The review date is not a valid date (use YYYY-MM-DD).")) from None
    if day <= today:
        raise DecisionError(_("The review date must be after today."))
    if day > today + timedelta(days=MAX_REVIEW_DAYS):
        raise DecisionError(_("Choose a review date within the next five years."))
    return day


def _snapshot(row: FindingDisposition, replaced_at: datetime) -> dict[str, Any]:
    """The state a change replaces, as it goes into ``history``."""
    return {
        "status": row.status,
        "reason": row.reason,
        "decided_by": str(row.decided_by),
        "decided_at": row.decided_at.isoformat(),
        "review_by": row.review_by.isoformat() if row.review_by else None,
        "replaced_at": replaced_at.isoformat(),
    }


def _create(
    session: Session,
    assessment_id: uuid.UUID,
    fingerprint: str,
    *,
    status: str,
    reason: str,
    user: User,
    at: datetime,
    review_by: date | None,
) -> FindingDisposition:
    row = FindingDisposition(
        assessment_id=assessment_id,
        fingerprint=fingerprint,
        status=status,
        reason=reason,
        decided_by=user.id,
        decided_at=at,
        review_by=review_by,
        history=[],
    )
    try:
        with session.begin_nested():  # a savepoint: losing the race must not poison the session
            session.add(row)
            session.flush()
    except IntegrityError:
        raise DecisionError(
            _(
                "Somebody else decided about this finding at the same moment. "
                "Reload the page and look at their decision."
            )
        ) from None
    return row


def decide(
    session: Session,
    assessment_id: uuid.UUID,
    finding: Finding,
    user: User,
    *,
    status: str,
    reason: str,
    review_by: str = "",
    today: date | None = None,
) -> FindingDisposition:
    """Accept a finding or mark it as a false positive; replaces an earlier decision about it.

    A reason is required. A review date is only for acceptances. The caller commits."""
    if status not in DECISIONS:
        raise DecisionError(
            _("Choose a decision: accept the finding or mark it as a false positive.")
        )
    reason = reason.strip()
    if not reason:
        raise DecisionError(_("Give a reason: the next reader needs it."))
    if len(reason) > MAX_REASON:
        raise DecisionError(
            _("The reason is too long (at most %(max)s characters).", max=MAX_REASON)
        )
    day = today or utc_now().date()
    review = parse_review_by(review_by, day) if status == ACCEPTED else None
    now = utc_now()

    existing = session.scalar(
        select(FindingDisposition)
        .where(
            FindingDisposition.assessment_id == assessment_id,
            FindingDisposition.fingerprint == finding.fingerprint,
        )
        .with_for_update()
    )
    if existing is None:
        row = _create(
            session,
            assessment_id,
            finding.fingerprint,
            status=status,
            reason=reason,
            user=user,
            at=now,
            review_by=review,
        )
    else:
        existing.history = [*existing.history, _snapshot(existing, now)][-MAX_HISTORY:]
        existing.status, existing.reason, existing.decided_by = status, reason, user.id
        existing.decided_at, existing.review_by = now, review
        row = existing
    log.info(
        "finding decision: assessment=%s rule=%s fingerprint=%s status=%s review_by=%s by=%s",
        assessment_id,
        finding.rule_id,
        finding.fingerprint,
        status,
        review,
        user.id,
    )
    return row


def reopen(session: Session, assessment_id: uuid.UUID, finding: Finding, user: User) -> bool:
    """Take a decision back: the finding is open again. ``False`` if nobody had decided about it.

    The decision row is deleted (its history goes with it); the log keeps who reopened what."""
    row = session.scalar(
        select(FindingDisposition)
        .where(
            FindingDisposition.assessment_id == assessment_id,
            FindingDisposition.fingerprint == finding.fingerprint,
        )
        .with_for_update()
    )
    if row is None:
        return False
    log.info(
        "finding reopened: assessment=%s rule=%s fingerprint=%s was=%s decided_by=%s by=%s",
        assessment_id,
        finding.rule_id,
        finding.fingerprint,
        row.status,
        row.decided_by,
        user.id,
    )
    session.delete(row)
    return True
