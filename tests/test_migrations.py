"""Tests verifying database extension wiring, session rollback isolation, and migrations."""

import os
import uuid
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask import Flask
from flask_migrate import downgrade, upgrade
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import create_app
from app.config import TestingConfig
from app.extensions import db

MIGRATIONS_DIRECTORY = Path(__file__).resolve().parents[1] / "migrations"


def _migration_head() -> str:
    alembic_config = Config(str(MIGRATIONS_DIRECTORY / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_DIRECTORY))
    head = ScriptDirectory.from_config(alembic_config).get_current_head()
    assert head is not None
    return head


def test_database_connectivity(app: Flask) -> None:
    """Verify that SQLAlchemy connects successfully to the database."""
    with app.app_context():
        result = db.session.execute(text("SELECT 1 AS alive")).scalar()
        assert result == 1


def test_transactional_rollback_isolation(app: Flask, db_session: Session) -> None:
    """Verify that db_session fixture isolates writes through rollback."""
    # Create a temporary table in the isolated session transaction
    db_session.execute(
        text("CREATE TEMPORARY TABLE test_isolation (id INT PRIMARY KEY, name VARCHAR(50));")
    )
    db_session.execute(text("INSERT INTO test_isolation (id, name) VALUES (1, 'initial_entry');"))

    count = db_session.execute(text("SELECT count(*) FROM test_isolation;")).scalar()
    assert count == 1


def test_alembic_config_loaded(app: Flask) -> None:
    """Verify Alembic configuration is bound to the migration extension."""
    migrate_extension = app.extensions.get("migrate")
    assert migrate_extension is not None
    assert migrate_extension.db is db


def test_test_harness_applied_current_migration_head(app: Flask) -> None:
    """Ensure ordinary tests exercise Alembic migrations rather than create_all()."""
    with app.app_context():
        revision: str = db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    assert revision == _migration_head()


def test_migration_upgrade_downgrade_cycle() -> None:
    """Run the complete migration cycle in its own generated disposable database."""
    # The environment is the only authority for destructive test setup. The
    # generated database name below cannot collide with a developer database.
    runtime_url = sa.engine.make_url(os.environ["TEST_DATABASE_URL"])

    database_name = f"due_diligence_test_{uuid.uuid4().hex}"
    admin_url = runtime_url.set(database="postgres")
    database_url = runtime_url.set(database=database_name)
    admin_engine = sa.create_engine(admin_url, isolation_level="AUTOCOMMIT")

    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')

    class MigrationTestingConfig(TestingConfig):
        SQLALCHEMY_DATABASE_URI = database_url.render_as_string(hide_password=False)

    migration_app = create_app(MigrationTestingConfig)
    try:
        with migration_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            assert (
                db.session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == _migration_head()
            )

            expected_tables = {
                "assessment",
                "auth_rate_limit_bucket",
                "job",
                "host",
                "check_result",
                "finding",
            }
            assert expected_tables <= set(sa.inspect(db.engine).get_table_names())

            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="base")
            remaining = set(sa.inspect(db.engine).get_table_names()) - {"alembic_version"}
            assert remaining == set()

            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            assert (
                db.session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == _migration_head()
            )
            db.session.remove()
            db.engine.dispose()
    finally:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE "{database_name}" WITH (FORCE)')
        admin_engine.dispose()
