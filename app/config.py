"""Centralized, validated environment configuration profiles."""

import datetime
import os
from typing import Any, ClassVar


class ConfigurationError(Exception):
    """Raised when application configuration fails validation."""


class BaseConfig:
    """Shared base configuration settings."""

    ENV: str = "base"
    DEBUG: bool = False
    TESTING: bool = False

    # Security & Sessions
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    SECURITY_PASSWORD_SALT: str = os.environ.get("SECURITY_PASSWORD_SALT", "")
    MFA_ENCRYPTION_KEY: str = os.environ.get("MFA_ENCRYPTION_KEY", "")

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_CHECK_DEFAULT: bool = False
    WTF_CSRF_TIME_LIMIT: int | None = 3600

    # Flask-Security-Too defaults
    SECURITY_REGISTERABLE: bool = False
    SECURITY_SEND_REGISTER_EMAIL: bool = False
    SECURITY_TWO_FACTOR: bool = True
    SECURITY_TWO_FACTOR_REQUIRED: bool = True
    SECURITY_TWO_FACTOR_ENABLED_METHODS: ClassVar[list[str]] = ["authenticator"]
    SECURITY_TOTP_ISSUER: str = "SaaS Technical Due Diligence"
    SECURITY_PASSWORD_HASH: str = "argon2"
    SECURITY_TRACKABLE: bool = True
    SECURITY_CHANGEABLE: bool = True
    SECURITY_URL_PREFIX: str = "/auth"
    SECURITY_POST_LOGIN_VIEW: str = "/"
    SECURITY_POST_LOGOUT_VIEW: str = "/auth/login"
    SECURITY_UNAUTHORIZED_VIEW: str = "/auth/login"
    SECURITY_FLASH_MESSAGES: bool = True
    SECURITY_LOGOUT_METHODS: ClassVar[list[str]] = ["GET", "POST"]
    SECURITY_TWO_FACTOR_ALWAYS_VALIDATE: bool = False
    SECURITY_TWO_FACTOR_LOGIN_VALIDITY: datetime.timedelta = datetime.timedelta(minutes=2)
    SECURITY_TWO_FACTOR_RESCUE_MAIL: bool = False
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS: bool = True
    SECURITY_TOTP_SECRETS: ClassVar[dict[str, str]] = {
        "1": os.environ.get("MFA_ENCRYPTION_KEY", "fallback-totp-key-32-chars-length")
    }

    # Database
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", "")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Governance & Scanning limits
    FOUR_EYES_ENABLED: bool = os.environ.get("FOUR_EYES_ENABLED", "false").lower() in ("true", "1")
    MAX_HOSTS_PER_RUN: int = int(os.environ.get("MAX_HOSTS_PER_RUN", "1000"))
    MAX_DISCOVERY_PAGES: int = int(os.environ.get("MAX_DISCOVERY_PAGES", "50"))

    # Evidence storage
    STORAGE_DIR: str = os.environ.get("STORAGE_DIR", "/var/data/evidence")

    # Anti-SSRF & Network settings
    EGRESS_DNS_RESOLVERS: ClassVar[list[str]] = ["1.1.1.1", "8.8.8.8"]
    EGRESS_CONNECT_TIMEOUT_SEC: float = 10.0
    EGRESS_READ_TIMEOUT_SEC: float = 20.0


class DevelopmentConfig(BaseConfig):
    """Configuration for local development."""

    ENV: str = "development"
    DEBUG: bool = True
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = False

    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY", "dev-insecure-secret-key-do-not-use-in-production-32b"
    )
    SECURITY_PASSWORD_SALT: str = os.environ.get("SECURITY_PASSWORD_SALT", "dev-password-salt-key")
    MFA_ENCRYPTION_KEY: str = os.environ.get(
        "MFA_ENCRYPTION_KEY", "dev-mfa-encryption-key-32-chars-long"
    )
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/web_due_diligence_dev",
    )
    STORAGE_DIR: str = os.environ.get("STORAGE_DIR", "./var/data/evidence")


class TestingConfig(BaseConfig):
    """Configuration for automated test runs."""

    ENV: str = "testing"
    DEBUG: bool = False
    TESTING: bool = True
    WTF_CSRF_ENABLED: bool = False
    SESSION_COOKIE_SECURE: bool = False

    SECRET_KEY: str = "test-secret-key-32-chars-minimum-length-req"
    SECURITY_PASSWORD_SALT: str = "test-password-salt-sample"
    MFA_ENCRYPTION_KEY: str = "test-mfa-encryption-key-32-bytes-len"
    SECURITY_TOTP_SECRETS: ClassVar[dict[str, str]] = {
        "1": "test-mfa-encryption-key-32-bytes-len"
    }
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/web_due_diligence_test",
    )
    STORAGE_DIR: str = os.environ.get("TEST_STORAGE_DIR", "./tmp/test_storage")


class ProductionConfig(BaseConfig):
    """Configuration for production environments with strict validation."""

    ENV: str = "production"
    DEBUG: bool = False
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"


def validate_config(config_obj: Any) -> None:
    """Validate configuration settings, enforcing security invariants and mandatory settings."""
    env = getattr(config_obj, "ENV", "base")
    secret_key = getattr(config_obj, "SECRET_KEY", "")
    db_uri = getattr(config_obj, "SQLALCHEMY_DATABASE_URI", "")
    storage_dir = getattr(config_obj, "STORAGE_DIR", "")
    max_hosts = getattr(config_obj, "MAX_HOSTS_PER_RUN", 0)
    max_pages = getattr(config_obj, "MAX_DISCOVERY_PAGES", 0)

    if not storage_dir or not str(storage_dir).strip():
        raise ConfigurationError("STORAGE_DIR must be specified and non-empty.")

    if not isinstance(max_hosts, int) or max_hosts <= 0:
        raise ConfigurationError("MAX_HOSTS_PER_RUN must be a positive integer.")

    if not isinstance(max_pages, int) or max_pages <= 0:
        raise ConfigurationError("MAX_DISCOVERY_PAGES must be a positive integer.")

    if env == "production":
        if not secret_key or len(secret_key) < 32:
            raise ConfigurationError(
                "SECRET_KEY must be set in production with at least 32 characters."
            )

        weak_keywords = ["dev", "insecure", "default", "test", "changeme", "secret"]
        if any(keyword in secret_key.lower() for keyword in weak_keywords):
            raise ConfigurationError("Production SECRET_KEY cannot contain weak/default patterns.")

        salt = getattr(config_obj, "SECURITY_PASSWORD_SALT", "")
        if not salt or len(salt) < 16:
            raise ConfigurationError(
                "SECURITY_PASSWORD_SALT must be set in production with at least 16 characters."
            )

        mfa_key = getattr(config_obj, "MFA_ENCRYPTION_KEY", "")
        if not mfa_key or len(mfa_key) < 16:
            raise ConfigurationError(
                "MFA_ENCRYPTION_KEY must be set in production with at least 16 characters."
            )

        if not db_uri or not db_uri.startswith("postgresql"):
            raise ConfigurationError(
                "Production SQLALCHEMY_DATABASE_URI must be a valid PostgreSQL connection URI."
            )
    elif env != "testing":
        if not db_uri:
            raise ConfigurationError("SQLALCHEMY_DATABASE_URI must be configured.")
