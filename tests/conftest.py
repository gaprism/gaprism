"""Pytest fixtures for the SaaS Due Diligence Platform."""

import os
from collections.abc import Generator

import pytest
import sqlalchemy as sa
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from sqlalchemy.orm import Session

from app import create_app
from app.config import TestingConfig
from app.extensions import db


class PostgresTestingConfig(TestingConfig):
    """Testing configuration pointing to accessible PostgreSQL instance."""

    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/due_diligence",
    )


@pytest.fixture(scope="session")
def app() -> Generator[Flask, None, None]:
    """Session-scoped Flask application instance configured for tests."""
    test_app = create_app(PostgresTestingConfig)
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        with db.engine.connect() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(sa.text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
                conn.commit()
            else:
                db.drop_all()


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
        session = Session(
            bind=connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        app._test_db_session = session

        yield session

        app._test_db_session = None
        session.close()
        transaction.rollback()
        connection.close()
