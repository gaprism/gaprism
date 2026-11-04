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


def test_accounts_get_an_optional_name_and_lose_it_again(database_url: str) -> None:
    """Migration 0007 adds the name; accounts that exist have none, and it can be undone."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0006_user_invitation")
            with db.engine.begin() as connection:
                connection.execute(
                    sa.text(
                        'INSERT INTO "user" (id, email, password, active, fs_uniquifier,'
                        " create_datetime, update_datetime, login_count) VALUES (:id,"
                        " 'old@example.org', 'x', true, :uniquifier, now(), now(), 0)"
                    ),
                    {"id": uuid.uuid4(), "uniquifier": uuid.uuid4().hex},
                )

            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            with db.engine.begin() as connection:
                assert connection.execute(sa.text('SELECT name FROM "user"')).scalar_one() is None
                connection.execute(sa.text('UPDATE "user" SET name = :name'), {"name": "Anna"})
            name = next(
                column
                for column in sa.inspect(db.engine).get_columns("user", schema=schema)
                if column["name"] == "name"
            )
            assert name["nullable"] and name["type"].length == 100

            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0006_user_invitation")
            columns = {c["name"] for c in sa.inspect(db.engine).get_columns("user", schema=schema)}
            assert "name" not in columns and "email" in columns
            with db.engine.begin() as connection:  # the account itself is still there
                assert connection.execute(sa.text('SELECT email FROM "user"')).scalar_one() == (
                    "old@example.org"
                )
            db.engine.dispose()
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_a_picture_belongs_to_one_account_goes_with_it_and_can_be_undone(
    database_url: str,
) -> None:
    """Migration 0008: the version on the account, and one stored picture for each account."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    owner = uuid.uuid4()
    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0007_user_name")
            with db.engine.begin() as connection:
                connection.execute(
                    sa.text(
                        'INSERT INTO "user" (id, email, password, active, fs_uniquifier,'
                        " create_datetime, update_datetime, login_count) VALUES (:id,"
                        " 'old@example.org', 'x', true, :uniquifier, now(), now(), 0)"
                    ),
                    {"id": owner, "uniquifier": uuid.uuid4().hex},
                )

            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            insert = sa.text("INSERT INTO user_image (id, user_id, content) VALUES (:id, :u, :c)")
            with db.engine.begin() as connection:
                query = sa.text('SELECT picture_version FROM "user"')
                assert connection.execute(query).scalar_one() is None  # no picture: no version
                connection.execute(insert, {"id": uuid.uuid4(), "u": owner, "c": b"\x00\x01\xff"})
                stored = sa.text("SELECT content FROM user_image")
                assert bytes(connection.execute(stored).scalar_one()) == b"\x00\x01\xff"
            with pytest.raises(sa.exc.IntegrityError), db.engine.begin() as connection:
                connection.execute(insert, {"id": uuid.uuid4(), "u": owner, "c": b"second"})
            with db.engine.begin() as connection:  # the picture goes with its account
                connection.execute(sa.text('DELETE FROM "user"'))
                assert connection.execute(sa.text("SELECT count(*) FROM user_image")).scalar() == 0

            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0007_user_name")
            inspector = sa.inspect(db.engine)
            assert "user_image" not in inspector.get_table_names(schema=schema)
            columns = {c["name"] for c in inspector.get_columns("user", schema=schema)}
            assert "picture_version" not in columns and "name" in columns
            db.engine.dispose()
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_accounts_get_an_optional_language_and_lose_it_again(database_url: str) -> None:
    """Migration 0009 adds the language of an account; accounts that exist have none."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    engine = sa.create_engine(database_url)
    try:
        migrated_app = make_app(database_url, schema)
        with migrated_app.app_context():
            upgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0008_user_picture")
            with db.engine.begin() as connection:
                connection.execute(
                    sa.text(
                        'INSERT INTO "user" (id, email, password, active, fs_uniquifier,'
                        " create_datetime, update_datetime, login_count) VALUES (:id,"
                        " 'old@example.org', 'x', true, :uniquifier, now(), now(), 0)"
                    ),
                    {"id": uuid.uuid4(), "uniquifier": uuid.uuid4().hex},
                )

            upgrade(directory=str(MIGRATIONS_DIRECTORY))
            with db.engine.begin() as connection:
                assert connection.execute(sa.text('SELECT locale FROM "user"')).scalar_one() is None
                connection.execute(sa.text('UPDATE "user" SET locale = :code'), {"code": "de_CH"})
            column = next(
                c
                for c in sa.inspect(db.engine).get_columns("user", schema=schema)
                if c["name"] == "locale"
            )
            assert column["nullable"] and column["type"].length == 10

            downgrade(directory=str(MIGRATIONS_DIRECTORY), revision="0008_user_picture")
            columns = {c["name"] for c in sa.inspect(db.engine).get_columns("user", schema=schema)}
            assert "locale" not in columns and "picture_version" in columns
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
