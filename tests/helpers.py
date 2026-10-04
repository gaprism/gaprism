"""Helpers shared by test modules (fixtures live in ``conftest.py``)."""

from pathlib import Path

from flask import Flask

from app import create_app
from app.config import TestingConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIRECTORY = PROJECT_ROOT / "migrations"


def make_app(database_url: str, schema: str) -> Flask:
    """Create an application bound to ``schema`` of the test database."""

    class DatabaseTestingConfig(TestingConfig):
        SQLALCHEMY_DATABASE_URI = database_url
        DB_SCHEMA = schema

    return create_app(DatabaseTestingConfig)
