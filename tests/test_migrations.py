"""The migrations create exactly what the models declare, and can be rolled back."""

import uuid

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
