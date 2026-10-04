"""Tests for the application factory and configuration validation."""

import subprocess
import sys
from typing import ClassVar

import pytest

from app import create_app
from app.config import (
    ConfigurationError,
    ProductionConfig,
    TestingConfig,
    validate_config,
)


def test_factory_creates_independent_instances() -> None:
    """Verify that multiple app instances have isolated configuration and state."""
    app1 = create_app("testing")
    app2 = create_app("testing")

    assert app1 is not app2
    assert app1.config["TESTING"] is True
    assert app2.config["TESTING"] is True

    app1.config["CUSTOM_ATTR"] = "instance_1"
    app2.config["CUSTOM_ATTR"] = "instance_2"

    assert app1.config["CUSTOM_ATTR"] == "instance_1"
    assert app2.config["CUSTOM_ATTR"] == "instance_2"


def test_factory_with_config_class() -> None:
    """Verify app creation passing a config class directly."""
    app = create_app(TestingConfig)
    assert app.config["ENV"] == "testing"
    assert app.config["TESTING"] is True


def test_factory_invalid_config_name() -> None:
    """Verify unknown profile strings raise ConfigurationError."""
    with pytest.raises(ConfigurationError, match="Unknown configuration profile"):
        create_app("nonexistent_profile")


def test_factory_rejects_invalid_config_object() -> None:
    """Reject objects that are neither profile names nor BaseConfig classes."""
    with pytest.raises(ConfigurationError, match="Invalid configuration object"):
        create_app(object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "schema",
    [
        'x"; DROP SCHEMA public CASCADE; --',
        "a -c statement_timeout=0",  # would smuggle a second libpq option
        "1leading_digit",
        "has space",
        "x" * 64,
    ],
)
def test_db_schema_must_be_a_plain_identifier(schema: str) -> None:
    """DB_SCHEMA ends up in a libpq options string, so anything but an identifier is refused."""

    class BadSchema(TestingConfig):
        DB_SCHEMA = schema

    with pytest.raises(ConfigurationError, match="DB_SCHEMA must be a plain identifier"):
        validate_config(BadSchema)
    with pytest.raises(ConfigurationError, match="DB_SCHEMA must be a plain identifier"):
        create_app(BadSchema)


def test_db_schema_sets_search_path_for_every_connection() -> None:
    """A configured schema becomes the connection search_path; none leaves the default."""

    class WithSchema(TestingConfig):
        DB_SCHEMA = "due_diligence"

    options = create_app(WithSchema).config["SQLALCHEMY_ENGINE_OPTIONS"]
    assert options["connect_args"]["options"] == "-c search_path=due_diligence"
    assert options["pool_pre_ping"] is True

    default_options = create_app(TestingConfig).config["SQLALCHEMY_ENGINE_OPTIONS"]
    assert "connect_args" not in default_options


def test_validate_config_negative_limits() -> None:
    """Verify negative or zero scan limits fail validation."""

    class BadLimitConfig(TestingConfig):
        MAX_HOSTS_PER_RUN = 0

    with pytest.raises(ConfigurationError, match="MAX_HOSTS_PER_RUN must be a positive integer"):
        validate_config(BadLimitConfig)

    class BadPageConfig(TestingConfig):
        MAX_DISCOVERY_PAGES = -5

    with pytest.raises(ConfigurationError, match="MAX_DISCOVERY_PAGES must be a positive integer"):
        validate_config(BadPageConfig)


def test_validate_production_config_weak_secrets() -> None:
    """Verify production fails fast on short or default secrets."""

    class WeakSecretProd(ProductionConfig):
        SECRET_KEY = "dev-insecure-key-12345678901234567890"
        SECURITY_PASSWORD_SALT = "long-enough-password-salt-key"
        MFA_ENCRYPTION_KEY = "long-enough-mfa-encryption-key-32b"
        SQLALCHEMY_DATABASE_URI = "postgresql+psycopg://user:pass@localhost:5432/db"

    with pytest.raises(ConfigurationError, match="cannot contain weak/default patterns"):
        validate_config(WeakSecretProd)

    class ShortSecretProd(ProductionConfig):
        SECRET_KEY = "short"
        SECURITY_PASSWORD_SALT = "long-enough-password-salt-key"
        MFA_ENCRYPTION_KEY = "long-enough-mfa-encryption-key-32b"
        SQLALCHEMY_DATABASE_URI = "postgresql+psycopg://user:pass@localhost:5432/db"

    with pytest.raises(ConfigurationError, match="at least 32 characters"):
        validate_config(ShortSecretProd)


def test_validate_production_config_valid() -> None:
    """Verify valid production config passes validation."""

    class ValidProd(ProductionConfig):
        SECRET_KEY = "a_very_strong_and_secure_random_production_key_32chars"
        SECURITY_PASSWORD_SALT = "a_strong_random_salt_16"
        MFA_ENCRYPTION_KEY = "a_strong_mfa_encryption_key_32"
        AUTH_RATE_LIMIT_KEY = "a_strong_auth_rate_limit_key_32_chars"
        SQLALCHEMY_DATABASE_URI = "postgresql+psycopg://user:pass@localhost:5432/prod_db"

    validate_config(ValidProd)


def test_empty_environment_values_keep_the_profile_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A .env copied from .env.example has empty lines; they must not wipe the defaults."""
    for name in ("SECRET_KEY", "REQUIRE_MFA", "MAX_HOSTS_PER_RUN", "CT_SOURCES", "DATABASE_URL"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("DB_SCHEMA", "")
    app = create_app("development")
    assert app.config["SECRET_KEY"] and "dev" in app.config["SECRET_KEY"]
    assert app.config["MAX_HOSTS_PER_RUN"] == 200
    assert app.config["CT_SOURCES"] == ["ctlogs", "certspotter", "crtsh"]
    assert app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql")
    assert app.config["DB_SCHEMA"] == ""


def test_production_still_fails_fast_when_a_secret_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(ConfigurationError, match="SECRET_KEY must be set in production"):
        create_app("production")


@pytest.mark.parametrize("setting", ["PROVIDER_TIMEOUT_SECONDS", "DISCOVERY_BUDGET_SECONDS"])
@pytest.mark.parametrize("bad", [0, -1, True, float("nan"), float("inf"), "30"])
def test_time_limits_must_be_positive_finite_numbers(setting: str, bad: object) -> None:
    config = type("BadLimit", (TestingConfig,), {setting: bad})
    with pytest.raises(ConfigurationError, match=f"{setting} must be a positive number"):
        validate_config(config)


def test_the_discovery_budget_can_be_set_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DISCOVERY_BUDGET_SECONDS", "12.5")
    assert create_app("development").config["DISCOVERY_BUDGET_SECONDS"] == 12.5
    monkeypatch.setenv("DISCOVERY_BUDGET_SECONDS", "soon")
    with pytest.raises(ConfigurationError, match="DISCOVERY_BUDGET_SECONDS must be a number"):
        create_app("development")


@pytest.mark.parametrize("setting", ["WORKER_THREADS", "PER_TARGET_CONCURRENCY"])
@pytest.mark.parametrize("bad", [0, -1, 65, True, "8"])
def test_worker_limits_must_be_small_positive_integers(setting: str, bad: object) -> None:
    config = type("BadWorker", (TestingConfig,), {setting: bad})
    with pytest.raises(ConfigurationError, match=f"{setting} must be an integer from 1 to 64"):
        validate_config(config)


def test_worker_limits_can_be_set_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKER_THREADS", "3")
    monkeypatch.setenv("PER_TARGET_CONCURRENCY", "2")
    config = create_app("development").config
    assert (config["WORKER_THREADS"], config["PER_TARGET_CONCURRENCY"]) == (3, 2)


def test_ct_settings_are_validated() -> None:
    class UnknownSource(TestingConfig):
        CT_SOURCES: ClassVar[list[str]] = ["ctlogs", "nonsense"]

    class NoSources(TestingConfig):
        CT_SOURCES: ClassVar[list[str]] = []

    class BadMode(TestingConfig):
        CT_MODE = "everything"

    for config, message in (
        (UnknownSource, "unknown: nonsense"),
        (NoSources, "at least one"),
        (BadMode, "CT_MODE must be"),
    ):
        with pytest.raises(ConfigurationError, match=message):
            validate_config(config)


def test_healthz_endpoint_and_security_headers() -> None:
    """Verify healthcheck endpoint and security headers."""
    app = create_app("testing")
    client = app.test_client()

    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"status": "healthy", "env": "testing"}

    # Verify security headers
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_import_has_no_runtime_side_effects() -> None:
    """Importing the package must not open sockets, run workers, or build an app."""
    probe = """
import socket
from unittest.mock import patch

with patch.object(socket, 'create_connection', side_effect=AssertionError('network access')):
    import app
    assert callable(app.create_app)
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
