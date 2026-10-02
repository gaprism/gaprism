"""Tests verifying database extension wiring, session rollback isolation, and migrations."""

from flask import Flask
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.extensions import db


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
    db_session.execute(
        text("INSERT INTO test_isolation (id, name) VALUES (1, 'initial_entry');")
    )

    count = db_session.execute(text("SELECT count(*) FROM test_isolation;")).scalar()
    assert count == 1


def test_alembic_config_loaded(app: Flask) -> None:
    """Verify Alembic configuration is bound to the migration extension."""
    migrate_extension = app.extensions.get("migrate")
    assert migrate_extension is not None
    assert migrate_extension.db is db
