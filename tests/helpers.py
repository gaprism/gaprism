"""Helpers shared by test modules (fixtures live in ``conftest.py``)."""

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Flask, g, has_app_context
from flask.testing import FlaskClient
from flask_security.utils import hash_password
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import create_app
from app.config import TestingConfig
from app.models import Assessment, AuditEvent, User

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIRECTORY = PROJECT_ROOT / "migrations"
NEUTRAL_BADGE = "bg-subtle text-muted"  # the info and muted tones: a fact, or nothing to report


def make_app(database_url: str, schema: str, **overrides: Any) -> Flask:
    """Create an application bound to ``schema`` of the test database.

    ``overrides`` replace configuration values, e.g. ``WTF_CSRF_ENABLED=True``.
    """

    class DatabaseTestingConfig(TestingConfig):
        SQLALCHEMY_DATABASE_URI = database_url
        DB_SCHEMA = schema

    for name, value in overrides.items():
        setattr(DatabaseTestingConfig, name, value)
    return create_app(DatabaseTestingConfig)


def audit_rows(session: Session, *actions: str) -> list[AuditEvent]:
    """The entries of the audit log, oldest first (only these actions when some are named)."""
    query = select(AuditEvent).order_by(AuditEvent.occurred_at, AuditEvent.id)
    if actions:
        query = query.where(AuditEvent.action.in_(actions))
    return list(session.scalars(query))


def create_user(session: Session, email: str | None = None) -> User:
    """Persist an active user with a throw-away password."""
    user = User(
        email=email or f"user-{uuid.uuid4().hex[:8]}@example.org",
        password=hash_password("Throwaway-Password-1"),
        active=True,
    )
    session.add(user)
    session.commit()
    return user


def create_assessment(
    session: Session, owner: User, domain: str = "example.com", visibility: str = "private"
) -> Assessment:
    """Persist an assessment owned by ``owner``."""
    assessment = Assessment(
        domain=domain, domain_display=domain, created_by=owner.id, visibility=visibility
    )
    session.add(assessment)
    session.commit()
    return assessment


def login_as(client: FlaskClient, user: User) -> None:
    """Start a signed-in session without the login form. Tests only: no such path exists in
    the application, which authenticates exclusively through Flask-Security.

    Tests that use the ``db_session`` fixture keep one application context open, and Flask
    reuses it for every request, so Flask-Login's per-request user cache on ``g`` would leak
    from one request to the next. Clearing it makes switching users behave as in production,
    where every request has its own context.
    """
    if has_app_context():
        g.pop("_login_user", None)
    with client.session_transaction() as state:
        state.clear()
        state["_user_id"] = user.fs_uniquifier
        state["_fresh"] = True
        state["fs_paa"] = datetime.now(UTC).timestamp()


def attributes(tag: str) -> dict[str, str]:
    """The ``name="value"`` pairs of one HTML tag (an attribute without a value is left out)."""
    return dict(re.findall(r'([a-z-]+)="([^"]*)"', tag))


def render_badge(label: str, tone: str) -> str:
    """The badge macro of components/ui.html on its own: no application, no database.

    Only the markup of the badge, without the line break the macro's ``set`` leaves in front of it.
    """
    app = Flask(__name__, template_folder=str(PROJECT_ROOT / "app" / "templates"))
    source = "{% from 'components/ui.html' import badge %}{{ badge(label, tone) }}"
    return app.jinja_env.from_string(source).render(label=label, tone=tone).strip()


def badge_classes(page: str, words: str) -> str:
    """The colour classes of the badge that says ``words``; fails when no badge does.

    A badge of the ok tone has a check mark before its words, which is skipped. Every badge that
    says the same words has to look the same, or the pages disagree about what they mean.
    """
    pattern = rf'<span class="badge ([^"]*)">(?:<svg\b.*?</svg>)?{re.escape(words)}</span>'
    found = set(re.findall(pattern, page, re.S))
    assert found, f"no badge says {words!r}"
    assert len(found) == 1, f"the badges that say {words!r} differ: {sorted(found)}"
    return found.pop()
