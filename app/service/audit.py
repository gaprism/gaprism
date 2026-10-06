"""The audit log: who did what, when, and to what.

``record`` adds a row to ``audit_event`` in the caller's transaction, so an entry exists exactly
when the change it records does, and writes the same fact to the ``app.audit`` logger. What goes in
is small and safe by construction: codes, ids, counts, names of domains; never a password, a secret
or text somebody typed (the reason of a decision stays on the decision).

Administrators read the log on the audit page and with ``flask audit list``. Nothing edits an entry;
the worker removes the oldest ones when ``AUDIT_RETENTION_DAYS`` has passed.
"""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from flask import has_request_context, request
from flask_security import current_user
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.audit import AUDIT_LOGGER
from app.i18n import gettext as _
from app.models import Assessment, AuditEvent, User
from app.models.base import utc_now

log = logging.getLogger(AUDIT_LOGGER)


def N_(message: str) -> str:  # noqa: N802 - the gettext marker: translated when shown, not here
    return message


PAGE_SIZE = 50
MAX_DETAILS = 20  # facts per entry
MAX_TEXT = 200  # characters of a text fact
_KEY = re.compile(r"[a-z][a-z0-9_]{0,31}")

# What can be recorded, in the words the audit page shows. The part before the dot is the group.
ACTIONS: dict[str, str] = {
    "auth.login": N_("Signed in"),
    "auth.login_failed": N_("Failed sign-in"),
    "auth.logout": N_("Signed out"),
    "auth.password_changed": N_("Changed the password"),
    "auth.mfa_changed": N_("Changed the two-factor setup"),
    "assessment.created": N_("Created the assessment"),
    "assessment.shared": N_("Shared the assessment with the team"),
    "assessment.unshared": N_("Made the assessment private"),
    "hosts.added": N_("Added hosts"),
    "hosts.removed": N_("Removed a host"),
    "scan.started": N_("Started a scan"),
    "scan.cancelled": N_("Cancelled the scan"),
    "scan.refused": N_("Was refused a scan: too many in the last hour"),
    "finding.accepted": N_("Accepted a finding"),
    "finding.false_positive": N_("Marked a finding as a false positive"),
    "finding.reopened": N_("Reopened a finding"),
    "export.report": N_("Opened the report"),
    "export.json": N_("Exported the scan as JSON"),
    "export.hosts_csv": N_("Exported the hosts as CSV"),
    "export.findings_csv": N_("Exported the findings as CSV"),
    "user.created": N_("Created an account"),
    "user.password_set": N_("Set a new password"),
    "user.activated": N_("Switched an account on"),
    "user.deactivated": N_("Switched an account off"),
    "user.admin_granted": N_("Made an account an administrator"),
    "user.admin_revoked": N_("Took the administrator role from an account"),
    "user.mfa_reset": N_("Forgot the authenticator of an account"),
}
GROUPS: dict[str, str] = {
    "auth": N_("Sign-in"),
    "assessment": N_("Assessments"),
    "hosts": N_("Hosts"),
    "scan": N_("Scans"),
    "finding": N_("Findings"),
    "export": N_("Exports"),
    "user": N_("Accounts"),
}


def action_label(action: str) -> str:
    """The action in words (the code itself for one this version does not know)."""
    return _(ACTIONS[action]) if action in ACTIONS else action


def group_label(group: str) -> str:
    return _(GROUPS[group]) if group in GROUPS else group


# --------------------------------------------------------------------------- writing


def _clean(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep the facts small and plain: scalars and short lists of them, a few, with tame names.
    A fact that is not known (None) is left out."""
    clean: dict[str, Any] = {}
    for key, value in (details or {}).items():
        if value is None or len(clean) >= MAX_DETAILS or not _KEY.fullmatch(str(key)):
            continue
        if isinstance(value, bool | int):
            clean[key] = value
        elif isinstance(value, float):
            clean[key] = value if math.isfinite(value) else str(value)  # JSON has no NaN
        elif isinstance(value, str):
            clean[key] = value[:MAX_TEXT]
        elif isinstance(value, list | tuple):
            clean[key] = [
                item if isinstance(item, bool | int | float) else str(item)[:MAX_TEXT]
                for item in value[:MAX_DETAILS]
            ]
        else:
            clean[key] = str(value)[:MAX_TEXT]
    return clean


def _current_actor() -> User | None:
    if has_request_context() and current_user and current_user.is_authenticated:
        return current_user._get_current_object()  # type: ignore[no-any-return]
    return None


def record(
    session: Session,
    action: str,
    *,
    actor: User | None = None,
    assessment: Assessment | uuid.UUID | None = None,
    subject: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> AuditEvent:
    """Add an entry to the audit log. The caller commits (with the change it records).

    ``actor`` defaults to the signed-in user of the request (none for a command line). An
    ``assessment`` (or its id) links the entry to it and puts the domain into the details.
    """
    who = actor or _current_actor()
    facts = _clean(details)
    target: Assessment | None = None
    if isinstance(assessment, Assessment):
        target = assessment
    elif assessment is not None:
        target = session.get(Assessment, assessment)  # none: no such assessment, no link then
    if target is not None:
        facts.setdefault("domain", target.domain)
    in_request = has_request_context()
    event = AuditEvent(
        source="web" if in_request else "cli",
        actor_id=who.id if who is not None else None,
        actor_email=who.email if who is not None else None,
        action=action,
        assessment_id=target.id if target is not None else None,
        subject=subject[:255] if subject else None,
        details=facts,
        remote_addr=((request.remote_addr or "")[:64] or None) if in_request else None,
    )
    session.add(event)
    session.flush()
    log.info(
        "%s actor=%s assessment=%s subject=%s details=%s",
        action,
        event.actor_id,
        event.assessment_id,
        json.dumps(event.subject),
        json.dumps(facts, sort_keys=True),
    )
    return event


# --------------------------------------------------------------------------- reading


@dataclass(frozen=True)
class EventPage:
    items: list[AuditEvent]
    total: int
    page: int
    per_page: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.per_page))


def list_events(
    session: Session,
    *,
    group: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    assessment_id: uuid.UUID | None = None,
    since: datetime | None = None,
    page: int = 1,
    per_page: int = PAGE_SIZE,
) -> EventPage:
    """The entries, newest first; ``actor`` is part of an e-mail address."""
    page = max(1, page)
    per_page = max(1, min(per_page, 200))
    query = select(AuditEvent)
    if group in GROUPS:
        query = query.where(AuditEvent.action.like(f"{group}.%"))
    if action in ACTIONS:
        query = query.where(AuditEvent.action == action)
    if actor:
        escaped = (
            actor.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        query = query.where(func.lower(AuditEvent.actor_email).like(f"%{escaped}%", escape="\\"))
    if assessment_id is not None:
        query = query.where(AuditEvent.assessment_id == assessment_id)
    if since is not None:
        query = query.where(AuditEvent.occurred_at >= since)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    page = min(page, max(1, -(-int(total) // per_page)))  # a page past the end shows the last one
    ordered = query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).limit(per_page)
    rows = session.scalars(ordered.offset((page - 1) * per_page))
    return EventPage(list(rows), int(total), page, per_page)


def facts(details: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The small facts of an entry as (name, text) pairs to show: lists joined, nothing empty, and
    not the domain (that is the assessment column, or the snapshot of a removed one)."""
    shown: list[tuple[str, str]] = []
    for key, value in details.items():
        if key == "domain" or value is None or value in ("", []):
            continue
        text = ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)
        shown.append((key, text))
    return shown


def assessment_names(session: Session, events: Sequence[AuditEvent]) -> dict[uuid.UUID, str]:
    """The domains of the assessments the entries are about (one query)."""
    ids = {event.assessment_id for event in events if event.assessment_id is not None}
    if not ids:
        return {}
    rows = session.execute(
        select(Assessment.id, Assessment.domain_display).where(Assessment.id.in_(ids))
    )
    return dict(rows.all())


# --------------------------------------------------------------------------- retention


def purge(session: Session, retention_days: int, *, now: datetime | None = None) -> int:
    """Remove entries older than the retention period (0 keeps everything). The caller commits.
    Returns how many were removed."""
    if retention_days <= 0:
        return 0
    cutoff = (now or utc_now()) - timedelta(days=retention_days)
    result = session.execute(delete(AuditEvent).where(AuditEvent.occurred_at < cutoff))
    return int(getattr(result, "rowcount", 0) or 0)
