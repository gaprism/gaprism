"""Pytest fixtures for the SaaS Due Diligence Platform."""

import os
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_migrate import downgrade, upgrade
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from app import create_app
from app.config import TestingConfig
from app.extensions import db

MIGRATIONS_DIRECTORY = Path(__file__).resolve().parents[1] / "migrations"


class PostgresTestingConfig(TestingConfig):
    """Testing configuration pointing to accessible PostgreSQL instance."""

    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "TEST_DATABASE_URL",
        "",
    )


@pytest.fixture(scope="session")
def app() -> Generator[Flask, None, None]:
    """Session-scoped Flask application instance configured for tests."""
    test_url = PostgresTestingConfig.SQLALCHEMY_DATABASE_URI
    if not test_url:
        pytest.fail("Set TEST_DATABASE_URL to a newly created disposable test database.")
    parsed = sa.engine.make_url(test_url)
    if not re.fullmatch(r"due_diligence_test_[a-f0-9]{32}", parsed.database or ""):
        pytest.fail("Test database name must be due_diligence_test_<32 random hex characters>.")
    test_app = create_app(PostgresTestingConfig)
    with test_app.app_context():
        if sa.inspect(db.engine).get_table_names():
            pytest.fail("Refusing to run against a non-empty database.")
        upgrade(directory=str(MIGRATIONS_DIRECTORY))
        try:
            yield test_app
        finally:
            db.session.remove()
            # The database name and initial emptiness were verified above. Use the
            # migration downgrade path so teardown also exercises the real schema.
            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="base")


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """HTTP client fixture for API and route testing."""
    return app.test_client()


@pytest.fixture
def cli_runner(app: Flask) -> FlaskCliRunner:
    """Flask CLI runner fixture for command testing."""
    return app.test_cli_runner()


@pytest.fixture
def db_session(app: Flask) -> Generator[Session, None, None]:
    """Transactional database session fixture providing rollback isolation per test."""
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
