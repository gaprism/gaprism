"""Pytest fixtures: one PostgreSQL schema per test session, a rollback per test.

The database role only needs to be allowed to create schemas in the test database (the
database owner is); no CREATEDB or superuser rights are required. The harness creates a
throwaway schema ``t_<random>``, runs the real migrations in it and drops it afterwards, so
it never touches existing schemas. Tests that need the database are skipped when
``TEST_DATABASE_URL`` is not set.
"""

import os
import uuid
from collections.abc import Generator
from typing import Any, cast

import pytest
import sqlalchemy as sa
from dotenv import dotenv_values
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_migrate import upgrade
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from app.extensions import db
from tests.helpers import MIGRATIONS_DIRECTORY, PROJECT_ROOT, make_app


def _test_database_url() -> str | None:
    """Read TEST_DATABASE_URL from the environment, falling back to the git-ignored .env."""
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        return url
    return dotenv_values(PROJECT_ROOT / ".env").get("TEST_DATABASE_URL") or None


@pytest.fixture(scope="session")
def database_url() -> str:
    """Connection URL of the test database; DB tests are skipped without one."""
    url = _test_database_url()
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set (see .env.example); database tests skipped")
    name = sa.engine.make_url(url).database or ""
    if "test" not in name:
        pytest.fail("TEST_DATABASE_URL must point to a database whose name contains 'test'.")
    return url


@pytest.fixture(scope="session")
def schema_name(database_url: str) -> Generator[str, None, None]:
    """A throwaway schema that exists for the whole test session."""
    name = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(sa.text(f'CREATE SCHEMA "{name}"'))
    try:
        yield name
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))
        engine.dispose()


@pytest.fixture(scope="session")
def app(database_url: str, schema_name: str) -> Generator[Flask, None, None]:
    """Session-scoped application with the migrated schema."""
    test_app = make_app(database_url, schema_name)
    with test_app.app_context():
        upgrade(directory=str(MIGRATIONS_DIRECTORY))
        try:
            yield test_app
        finally:
            db.session.remove()
            db.engine.dispose()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """HTTP client fixture for route testing."""
    return app.test_client()


@pytest.fixture
def cli_runner(app: Flask) -> FlaskCliRunner:
    """Flask CLI runner fixture for command testing."""
    return app.test_cli_runner()


@pytest.fixture
def db_session(app: Flask) -> Generator[Session, None, None]:
    """Session whose changes, commits included, are rolled back after each test."""
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        original_session = db.session
        test_sessions = scoped_session(
            sessionmaker(
                bind=connection,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            )
        )
        db.session = cast(Any, test_sessions)
        session = test_sessions()
        try:
            yield session
        finally:
            test_sessions.remove()
            db.session = original_session
            transaction.rollback()
            connection.close()
