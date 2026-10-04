"""Centralized, validated environment configuration profiles."""

import datetime
import math
import os
import re
from copy import deepcopy
from typing import Any, ClassVar


class ConfigurationError(Exception):
    """Raised when application configuration fails validation."""


# A plain identifier: it ends up in a libpq `options` string, so nothing else is allowed.
_SCHEMA_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")

# Names accepted in CT_SOURCES (kept here so that config validation needs no imports).
CT_SOURCE_KEYS = ("ctlogs", "certspotter", "crtsh")


class BaseConfig:
    """Shared base configuration settings."""

    ENV: str = "base"
    DEBUG: bool = False
    TESTING: bool = False

    # Security & Sessions
    SECRET_KEY: str = ""
    SECURITY_PASSWORD_SALT: str = ""
    MFA_ENCRYPTION_KEY: str = ""

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_CHECK_DEFAULT: bool = True
    WTF_CSRF_TIME_LIMIT: int | None = 3600

    # MFA is always available; REQUIRE_MFA decides whether enrolment is forced at first login.
    # Derived into SECURITY_TWO_FACTOR_REQUIRED by resolve_config(). On by default.
    REQUIRE_MFA: bool = True

    # UI languages offered (first = default); catalogs live in app/translations
    LANGUAGES: ClassVar[list[str]] = ["en"]

    # Flask-Security-Too defaults
    SECURITY_REGISTERABLE: bool = False
    SECURITY_SEND_REGISTER_EMAIL: bool = False
    SECURITY_TWO_FACTOR: bool = True
    SECURITY_TWO_FACTOR_REQUIRED: bool = True
    SECURITY_TWO_FACTOR_ENABLED_METHODS: ClassVar[list[str]] = ["authenticator"]
    SECURITY_TOTP_ISSUER: str = "Web Due Diligence"
    SECURITY_PASSWORD_HASH: str = "argon2"
    SECURITY_TRACKABLE: bool = True
    SECURITY_CHANGEABLE: bool = True
    SECURITY_URL_PREFIX: str = "/auth"
    SECURITY_POST_LOGIN_VIEW: str = "/"
    SECURITY_POST_LOGOUT_VIEW: str = "/auth/login"
    SECURITY_UNAUTHORIZED_VIEW: str = "/auth/login"
    SECURITY_FLASH_MESSAGES: bool = True
    SECURITY_RETURN_GENERIC_RESPONSES: bool = True
    SECURITY_LOGOUT_METHODS: ClassVar[list[str]] = ["POST"]
    SECURITY_CHANGE_URL: str = "/change-password"
    SECURITY_TWO_FACTOR_ALWAYS_VALIDATE: bool = True
    SECURITY_TWO_FACTOR_LOGIN_VALIDITY: datetime.timedelta = datetime.timedelta(minutes=2)
    SECURITY_TWO_FACTOR_RESCUE_MAIL: bool = False
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS: bool = False
    SECURITY_TOTP_SECRETS: ClassVar[dict[str, str]] = {}

    # Authentication abuse controls
    AUTH_RATE_LIMIT_KEY: str = ""
    AUTH_RATE_LIMIT_FAILURES: int = 5
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 15 * 60

    # Database
    SQLALCHEMY_DATABASE_URI: str = ""
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict[str, Any]] = {"pool_pre_ping": True}
    # Empty = the server's default schema. Set it when the role cannot write to `public`
    # (shared servers): `flask db upgrade` creates the schema and the app uses it.
    DB_SCHEMA: str = ""

    # Scanning limits
    MAX_HOSTS_PER_RUN: int = 200
    MAX_DISCOVERY_PAGES: int = 50
    # `flask worker` runs this many checks at once; PER_TARGET_CONCURRENCY caps how many of them
    # may belong to the same scan (= the same assessed domain) so no target is flooded.
    WORKER_THREADS: int = 8
    PER_TARGET_CONCURRENCY: int = 4
    # Domains (and everything below them) that may never be assessed, e.g. your own
    # infrastructure. Comma-separated in the environment.
    BLOCKED_DOMAINS: ClassVar[list[str]] = []

    # Certificate Transparency discovery. CT_SOURCES lists the sources in order; CT_MODE `union`
    # asks every source and merges, `first` stops at the first that answers.
    CT_SOURCES: ClassVar[list[str]] = ["ctlogs", "certspotter", "crtsh"]
    CT_MODE: str = "union"
    CTLOGS_API_KEY: str = ""  # optional: lifts the keyless page and rate limits
    CERTSPOTTER_TOKEN: str = ""  # optional: raises the unauthenticated rate limit
    # Total time discovery waits for its sources (they run in parallel); a slower source is
    # reported as "budget_exceeded" instead of holding the scan up.
    DISCOVERY_BUDGET_SECONDS: float = 45.0

    # Outgoing requests to public provider APIs
    USER_AGENT: str = "WebDueDiligence/0.1 (+https://github.com/stalpers/web_due_diligence)"
    PROVIDER_TIMEOUT_SECONDS: float = 20.0

    # Anti-SSRF & network settings
    EGRESS_DNS_RESOLVERS: ClassVar[list[str]] = ["1.1.1.1", "8.8.8.8"]
    EGRESS_CONNECT_TIMEOUT_SEC: float = 10.0
    EGRESS_READ_TIMEOUT_SEC: float = 20.0


class DevelopmentConfig(BaseConfig):
    """Configuration for local development."""

    ENV: str = "development"
    DEBUG: bool = True
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = False
    REQUIRE_MFA: bool = False  # convenient locally; production defaults to True

    SECRET_KEY: str = "dev-insecure-secret-key-do-not-use-in-production-32b"
    SECURITY_PASSWORD_SALT: str = "dev-password-salt-key"
    MFA_ENCRYPTION_KEY: str = "dev-mfa-encryption-key-32-chars-long"
    AUTH_RATE_LIMIT_KEY: str = "dev-auth-rate-limit-key-32-chars-long"
    SQLALCHEMY_DATABASE_URI: str = (
        "postgresql+psycopg://postgres:postgres@localhost:5432/web_due_diligence_dev"
    )


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
    AUTH_RATE_LIMIT_KEY: str = "test-auth-rate-limit-key-32-bytes-len"
    SECURITY_TOTP_SECRETS: ClassVar[dict[str, str]] = {"1": "test-mfa-encryption-key-32-bytes-len"}
    SQLALCHEMY_DATABASE_URI: str = (
        "postgresql+psycopg://postgres:postgres@localhost:5432/web_due_diligence_test"
    )


class ProductionConfig(BaseConfig):
    """Configuration for production environments with strict validation."""

    ENV: str = "production"
    DEBUG: bool = False
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"


def validate_db_schema(schema: str) -> None:
    """Reject anything but a plain identifier (it is used in a libpq options string)."""
    if schema and not _SCHEMA_NAME.fullmatch(schema):
        raise ConfigurationError("DB_SCHEMA must be a plain identifier (letters, digits, _).")


def validate_config(config_obj: Any) -> None:
    """Validate configuration settings, enforcing security invariants and mandatory settings."""
    env = getattr(config_obj, "ENV", "base")
    secret_key = getattr(config_obj, "SECRET_KEY", "")
    db_uri = getattr(config_obj, "SQLALCHEMY_DATABASE_URI", "")
    max_hosts = getattr(config_obj, "MAX_HOSTS_PER_RUN", 0)
    max_pages = getattr(config_obj, "MAX_DISCOVERY_PAGES", 0)
    auth_rate_limit_key = getattr(config_obj, "AUTH_RATE_LIMIT_KEY", "")
    auth_rate_limit_failures = getattr(config_obj, "AUTH_RATE_LIMIT_FAILURES", 0)
    auth_rate_limit_window = getattr(config_obj, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 0)

    validate_db_schema(getattr(config_obj, "DB_SCHEMA", ""))

    if not isinstance(max_hosts, int) or max_hosts <= 0:
        raise ConfigurationError("MAX_HOSTS_PER_RUN must be a positive integer.")

    if not isinstance(max_pages, int) or max_pages <= 0:
        raise ConfigurationError("MAX_DISCOVERY_PAGES must be a positive integer.")

    for name in ("WORKER_THREADS", "PER_TARGET_CONCURRENCY"):
        value = getattr(config_obj, name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 64:
            raise ConfigurationError(f"{name} must be an integer from 1 to 64.")

    ct_sources = list(getattr(config_obj, "CT_SOURCES", []))
    unknown_sources = sorted(set(ct_sources) - set(CT_SOURCE_KEYS))
    if not ct_sources or unknown_sources:
        raise ConfigurationError(
            f"CT_SOURCES must list at least one of {', '.join(CT_SOURCE_KEYS)}"
            + (f" (unknown: {', '.join(unknown_sources)})." if unknown_sources else ".")
        )
    if getattr(config_obj, "CT_MODE", "") not in ("union", "first"):
        raise ConfigurationError("CT_MODE must be 'union' or 'first'.")
    for name in ("PROVIDER_TIMEOUT_SECONDS", "DISCOVERY_BUDGET_SECONDS"):
        number = getattr(config_obj, name, 0)
        if (
            not isinstance(number, int | float)
            or isinstance(number, bool)
            or not math.isfinite(number)
            or number <= 0
        ):
            raise ConfigurationError(f"{name} must be a positive number.")

    if not isinstance(auth_rate_limit_failures, int) or auth_rate_limit_failures <= 0:
        raise ConfigurationError("AUTH_RATE_LIMIT_FAILURES must be a positive integer.")
    if not isinstance(auth_rate_limit_window, int) or auth_rate_limit_window <= 0:
        raise ConfigurationError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be a positive integer.")

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

        if not auth_rate_limit_key or len(auth_rate_limit_key) < 32:
            raise ConfigurationError(
                "AUTH_RATE_LIMIT_KEY must be set in production with at least 32 characters."
            )

        if not db_uri or not db_uri.startswith("postgresql"):
            raise ConfigurationError(
                "Production SQLALCHEMY_DATABASE_URI must be a valid PostgreSQL connection URI."
            )
    elif env != "testing":
        if not db_uri:
            raise ConfigurationError("SQLALCHEMY_DATABASE_URI must be configured.")


def resolve_config(config_class: type[BaseConfig], read_environment: bool) -> type[BaseConfig]:
    """Build independent configuration values for this factory invocation."""
    values = {
        name: deepcopy(getattr(config_class, name)) for name in dir(config_class) if name.isupper()
    }
    if read_environment:
        environment_keys = {
            "SECRET_KEY": "SECRET_KEY",
            "SECURITY_PASSWORD_SALT": "SECURITY_PASSWORD_SALT",
            "MFA_ENCRYPTION_KEY": "MFA_ENCRYPTION_KEY",
            "AUTH_RATE_LIMIT_KEY": "AUTH_RATE_LIMIT_KEY",
            "AUTH_RATE_LIMIT_FAILURES": "AUTH_RATE_LIMIT_FAILURES",
            "AUTH_RATE_LIMIT_WINDOW_SECONDS": "AUTH_RATE_LIMIT_WINDOW_SECONDS",
            "SQLALCHEMY_DATABASE_URI": "TEST_DATABASE_URL"
            if config_class.TESTING
            else "DATABASE_URL",
            "DB_SCHEMA": "DB_SCHEMA",
            "REQUIRE_MFA": "REQUIRE_MFA",
            "MAX_HOSTS_PER_RUN": "MAX_HOSTS_PER_RUN",
            "MAX_DISCOVERY_PAGES": "MAX_DISCOVERY_PAGES",
            "WORKER_THREADS": "WORKER_THREADS",
            "PER_TARGET_CONCURRENCY": "PER_TARGET_CONCURRENCY",
            "BLOCKED_DOMAINS": "BLOCKED_DOMAINS",
            "CT_SOURCES": "CT_SOURCES",
            "CT_MODE": "CT_MODE",
            "CTLOGS_API_KEY": "CTLOGS_API_KEY",
            "CERTSPOTTER_TOKEN": "CERTSPOTTER_TOKEN",
            "USER_AGENT": "USER_AGENT",
            "PROVIDER_TIMEOUT_SECONDS": "PROVIDER_TIMEOUT_SECONDS",
            "DISCOVERY_BUDGET_SECONDS": "DISCOVERY_BUDGET_SECONDS",
        }
        for key, env_key in environment_keys.items():
            if env_key not in os.environ:
                continue
            raw = os.environ[env_key]
            if raw == "" and values[key] != "":
                # An empty line in .env (copied from .env.example) means "not set": keep the
                # profile default. Settings whose default is empty stay empty, so production
                # still fails fast on a missing secret.
                continue
            if isinstance(values[key], bool):
                if raw.lower() not in ("true", "false", "1", "0"):
                    raise ConfigurationError(f"{env_key} must be true or false.")
                values[key] = raw.lower() in ("true", "1")
            elif isinstance(values[key], int):
                try:
                    values[key] = int(raw)
                except ValueError as exc:
                    raise ConfigurationError(f"{env_key} must be an integer.") from exc
            elif isinstance(values[key], float):
                try:
                    values[key] = float(raw)
                except ValueError as exc:
                    raise ConfigurationError(f"{env_key} must be a number.") from exc
            elif isinstance(values[key], list):
                values[key] = [part.strip().lower() for part in raw.split(",") if part.strip()]
            else:
                values[key] = raw
    values["SECURITY_TOTP_SECRETS"] = {"1": values["MFA_ENCRYPTION_KEY"]}
    values["SECURITY_TWO_FACTOR_REQUIRED"] = bool(values["REQUIRE_MFA"])

    schema = str(values.get("DB_SCHEMA", ""))
    validate_db_schema(schema)
    if schema:
        options = dict(values["SQLALCHEMY_ENGINE_OPTIONS"])
        options["connect_args"] = {
            **options.get("connect_args", {}),
            "options": f"-c search_path={schema}",
        }
        values["SQLALCHEMY_ENGINE_OPTIONS"] = options
    return type("ResolvedConfig", (config_class,), values)
