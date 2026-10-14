"""The migrations create exactly what the models declare, and can be rolled back."""

import logging
import uuid

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from flask_migrate import downgrade, upgrade

from app.extensions import db
from tests.helpers import MIGRATIONS_DIRECTORY, make_app


def test_models_match_migrations(app: Flask) -> None:
    """A model change without a migration (or the reverse) fails here."""
    with app.app_context(), db.engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, db.metadata) == []


def test_running_migrations_leaves_existing_loggers_enabled(database_url: str) -> None:
    """Alembic's logging setup disables existing loggers by default, which hid later errors."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    logger = logging.getLogger("app.service.discovery.service")
    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            db.engine.dispose()
        assert not logger.disabled
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_upgrade_and_downgrade_round_trip(database_url: str) -> None:
    """Upgrade creates the tables in the configured schema; downgrade removes them again."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            tables = set(sa.inspect(db.engine).get_table_names(schema=schema))
            assert {"assessment", "scan", "host", "check_result", "finding", "user"} <= tables
            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="base")
            assert set(sa.inspect(db.engine).get_table_names(schema=schema)) <= {"alembic_version"}
            db.engine.dispose()
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_visibility_team_becomes_shared_and_back(database_url: str) -> None:
    """Migration 0005 renames the stored value, the constraint follows, and it can be undone."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    owner = uuid.uuid4()

    def insert(connection: sa.Connection, domain: str, visibility: str) -> None:
        connection.execute(
            sa.text(
                "INSERT INTO assessment (id, domain, domain_display, visibility, created_by,"
                " created_at, updated_at) VALUES (:id, :domain, :domain, :visibility, :owner,"
                " now(), now())"
            ),
            {"id": uuid.uuid4(), "domain": domain, "visibility": visibility, "owner": owner},
        )

    def stored(connection: sa.Connection) -> dict[str, str]:
        rows = connection.execute(sa.text("SELECT domain, visibility FROM assessment")).all()
        return {domain: visibility for domain, visibility in rows}

    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0004_assessment_archive")
            with db.engine.begin() as connection:
                connection.execute(
                    sa.text(
                        'INSERT INTO "user" (id, email, password, active, fs_uniquifier,'
                        " create_datetime, update_datetime, login_count) VALUES (:id,"
                        " 'owner@example.org', 'x', true, :uniquifier, now(), now(), 0)"
                    ),
                    {"id": owner, "uniquifier": uuid.uuid4().hex},
                )
                insert(connection, "private.example", "private")
                insert(connection, "shared.example", "team")

            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            with db.engine.begin() as connection:
                assert stored(connection) == {
                    "private.example": "private",
                    "shared.example": "shared",
                }
            for refused in ("team", "everyone"):  # the retired name is not stored any more
                with pytest.raises(sa.exc.IntegrityError), db.engine.begin() as connection:
                    insert(connection, "refused.example", refused)
            with db.engine.begin() as connection:
                insert(connection, "accepted.example", "shared")

            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0004_assessment_archive")
            with db.engine.begin() as connection:
                assert stored(connection) == {
                    "private.example": "private",
                    "shared.example": "team",
                    "accepted.example": "team",
                }
            with pytest.raises(sa.exc.IntegrityError), db.engine.begin() as connection:
                insert(connection, "refused.example", "shared")
            db.engine.dispose()
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()
