"""Helpers shared by test modules (fixtures live in ``conftest.py``)."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Flask
from flask.testing import FlaskClient
from flask_security.utils import hash_password
from sqlalchemy.orm import Session

from app import create_app
from app.config import TestingConfig
from app.models import Assessment, User

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIRECTORY = PROJECT_ROOT / "migrations"


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
    the application, which authenticates exclusively through Flask-Security."""
    with client.session_transaction() as state:
        state.clear()
        state["_user_id"] = user.fs_uniquifier
        state["_fresh"] = True
        state["fs_paa"] = datetime.now(UTC).timestamp()
