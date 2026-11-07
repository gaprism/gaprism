"""Centralized, validated environment configuration profiles."""

import datetime
import ipaddress
import math
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, ClassVar

from app.messages import N_


class ConfigurationError(Exception):
    """Raised when application configuration fails validation."""


# A plain identifier: it ends up in a libpq `options` string, so nothing else is allowed.
_SCHEMA_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")

# Names accepted in CT_SOURCES (kept here so that config validation needs no imports).
CT_SOURCE_KEYS = ("ctlogs", "certspotter", "crtsh")

# Lookups of the assessed *domain* at a third party: the registry (RDAP), hstspreload.org, Have I
# Been Pwned (on by default) and Mozilla's HTTP Observatory (opt-in: Mozilla's scanner then requests
# the domain's home page, and its result is public on MDN). EXTERNAL_DOMAIN_LOOKUPS lists the ones
# that are on (`none` switches all off).
EXTERNAL_LOOKUP_KEYS = ("rdap", "hsts_preload", "hibp", "observatory")
EXTERNAL_LOOKUP_DEFAULTS = ("rdap", "hsts_preload", "hibp")

# Security DNS resolvers that refuse names their threat intelligence flags as malicious (the
# reputation check asks them about every host: Quad9 and Cloudflare's 1.1.1.2). REPUTATION_RESOLVERS
# lists the ones to ask (`none` switches the check off); app/checks/reputation.py knows their
# addresses.
REPUTATION_RESOLVER_KEYS = ("quad9", "cloudflare")

# Offline blocklists of hosts and addresses that serve malware or phishing: `flask datasets update`
# downloads them and the blocklists check matches them on this machine. BLOCKLIST_PROVIDERS lists
# the ones to download and use (`none` switches the check off); app/service/blocklists.py knows
# where each comes from (URLhaus and Feodo Tracker of abuse.ch, Phishing.Database). URLhaus is free
# under abuse.ch's fair use principles and use for commercial needs may require a paid licence, so
# it is off until the operator adds it: a source whose terms need a decision is opt-in.
BLOCKLIST_PROVIDER_KEYS = ("urlhaus", "phishing", "feodo")
BLOCKLIST_PROVIDER_DEFAULTS = ("phishing", "feodo")

# Where the assessed hosts may be located (ISO 3166-1 alpha-2, upper case): the EU-27, the EEA
# (IS, LI, NO) and CH. Hosts outside this area raise LOCATION_OUTSIDE_EU_CH (see docs/rules.md).
DEFAULT_DATA_LOCATION_ALLOWED = (
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
    "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",  # EU-27
    "IS", "LI", "NO",  # EEA
    "CH",
)  # fmt: skip
_COUNTRY_CODE = re.compile(r"[A-Z]{2}")

# Values of PORTS_PROVIDER: `auto` is the Shodan host API when a key is set and off otherwise. The
# keyless InternetDB is free for non-commercial use only, so it runs only when `internetdb` asks.
PORTS_PROVIDERS = ("auto", "shodan", "internetdb", "off")
MAX_PORTS_CACHE_HOURS = 30 * 24  # the worker deletes cache entries after 30 days
MAX_TRUSTED_PROXIES = 5  # reverse proxies in front of the app that TRUSTED_PROXY_COUNT may name
MAX_HOSTS_CEILING = 2000  # the most hosts one scan may review, whatever MAX_HOSTS_PER_RUN says
MAX_SCANS_PER_HOUR_CEILING = 1000  # upper bound of MAX_SCANS_PER_USER_PER_HOUR
MAX_AUDIT_RETENTION_DAYS = 3650  # upper bound of AUDIT_RETENTION_DAYS (ten years)
MAX_INVITATION_HOURS = 168  # upper bound of INVITATION_HOURS (one week)


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

    # No request is larger than this: a profile picture (at most 2 MB) is the biggest thing anybody
    # sends. The bound is global because Flask-WTF checks the CSRF token of every POST before any
    # view runs, and that reads the whole body; a limit set inside the view would come too late.
    MAX_CONTENT_LENGTH: int = 3 * 1024 * 1024

    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_CHECK_DEFAULT: bool = True
    WTF_CSRF_TIME_LIMIT: int | None = 3600

    # MFA is always available; REQUIRE_MFA decides whether enrolment is forced at first login.
    # Derived into SECURITY_TWO_FACTOR_REQUIRED by resolve_config(). On by default.
    REQUIRE_MFA: bool = True

    # UI languages offered (first = default); catalogs live in app/translations. With more than
    # one the account menu has a Language group; the choice is user.locale (see app/i18n.py).
    # de_CH is German as written in Switzerland; a language that is listed here must be complete
    # and compiled (tests/test_translations.py), see docs/translation.md.
    LANGUAGES: ClassVar[list[str]] = ["en", "de_CH"]

    # Flask-Security-Too defaults
    SECURITY_REGISTERABLE: bool = False
    SECURITY_SEND_REGISTER_EMAIL: bool = False
    # There is no mail server: with this on, changing a password failed with a 500 after the new
    # hash was stored. An administrator sets other people's passwords on the command line.
    SECURITY_SEND_PASSWORD_CHANGE_EMAIL: bool = False
    SECURITY_TWO_FACTOR: bool = True
    SECURITY_TWO_FACTOR_REQUIRED: bool = True
    SECURITY_TWO_FACTOR_ENABLED_METHODS: ClassVar[list[str]] = ["authenticator"]
    SECURITY_TOTP_ISSUER: str = "Gaprism"
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
    # The same minimum as the command line and the invitation page (app.service.users): the
    # library's own is 8, which let a password be changed to one that no other screen accepts.
    SECURITY_PASSWORD_LENGTH_MIN: int = 12
    # What the sign-in screen says when something goes wrong: what happened and what to do, in the
    # voice of the brand (the library's own words are terse). The first one is the answer for an
    # unknown account and for a wrong password alike. N_ lists each sentence for the catalogue;
    # app.i18n.SecurityDomain looks it up when the library shows it.
    SECURITY_MSG_GENERIC_AUTHN_FAILED: ClassVar[tuple[str, str]] = (
        N_("The email address or password is not correct. Check them and try again."),
        "error",
    )
    SECURITY_MSG_TWO_FACTOR_INVALID_TOKEN: ClassVar[tuple[str, str]] = (
        N_(
            "The code is not correct or has expired. "
            "Enter the current code from your authenticator app."
        ),
        "error",
    )
    SECURITY_MSG_TWO_FACTOR_PERMISSION_DENIED: ClassVar[tuple[str, str]] = (
        N_("The sign-in has expired. Enter your email address and password again."),
        "error",
    )
    # The password and two-factor pages, the same way. The one for an empty password serves all
    # three fields of the form, so it names none of them.
    SECURITY_MSG_INVALID_PASSWORD: ClassVar[tuple[str, str]] = (
        N_("The current password is not correct. Enter the password you sign in with."),
        "error",
    )
    SECURITY_MSG_RETYPE_PASSWORD_MISMATCH: ClassVar[tuple[str, str]] = (
        N_("The two new passwords are not the same. Enter the same password twice."),
        "error",
    )
    SECURITY_MSG_PASSWORD_INVALID_LENGTH: ClassVar[tuple[str, str]] = (
        N_("The new password is too short. Use at least %(length)s characters."),
        "error",
    )
    SECURITY_MSG_PASSWORD_NOT_PROVIDED: ClassVar[tuple[str, str]] = (
        N_("This field is empty. Enter a password."),
        "error",
    )
    SECURITY_MSG_PASSWORD_IS_THE_SAME: ClassVar[tuple[str, str]] = (
        N_("The new password is the same as the current one. Choose a different password."),
        "error",
    )
    SECURITY_MSG_PASSWORD_CHANGE: ClassVar[tuple[str, str]] = (
        N_("Your password has been changed."),
        "success",
    )
    SECURITY_MSG_TWO_FACTOR_DISABLED: ClassVar[tuple[str, str]] = (
        N_("Two-factor authentication is turned off."),
        "success",
    )
    SECURITY_MSG_TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL: ClassVar[tuple[str, str]] = (
        N_("Two-factor authentication is set up. Use your authenticator app at your next sign-in."),
        "success",
    )
    SECURITY_MSG_TWO_FACTOR_LOGIN_SUCCESSFUL: ClassVar[tuple[str, str]] = (
        N_("Your code is confirmed."),
        "success",
    )
    SECURITY_MSG_TWO_FACTOR_SETUP_EXPIRED: ClassVar[tuple[str, str]] = (
        N_("The setup took too long: it must be finished within %(within)s. Start again."),
        "error",
    )
    SECURITY_MSG_TWO_FACTOR_METHOD_NOT_AVAILABLE: ClassVar[tuple[str, str]] = (
        N_("That method is not available. Use the authenticator app."),
        "error",
    )
    SECURITY_MSG_REAUTHENTICATION_REQUIRED: ClassVar[tuple[str, str]] = (
        N_("Enter your password to continue."),
        "info",
    )
    SECURITY_MSG_REAUTHENTICATION_SUCCESSFUL: ClassVar[tuple[str, str]] = (
        N_("Your password is confirmed."),
        "info",
    )
    # The library's own words for what the screens can still show, worded as it has them (the
    # categories are its too). Listing them here puts them in the catalogue; the ones found by
    # running the sign-in, password and two-factor screens are these.
    SECURITY_MSG_UNAUTHENTICATED: ClassVar[tuple[str, str]] = (
        N_("You must sign in to view this resource."),
        "error",
    )
    SECURITY_MSG_UNAUTHORIZED: ClassVar[tuple[str, str]] = (
        N_("You do not have permission to view this resource."),
        "error",
    )
    SECURITY_MSG_ANONYMOUS_USER_REQUIRED: ClassVar[tuple[str, str]] = (
        N_("You can only access this endpoint when not logged in."),
        "error",
    )
    SECURITY_MSG_DISABLED_ACCOUNT: ClassVar[tuple[str, str]] = (N_("Account is disabled."), "error")
    SECURITY_MSG_USER_DOES_NOT_EXIST: ClassVar[tuple[str, str]] = (
        N_("Specified user does not exist"),
        "error",
    )
    SECURITY_MSG_EMAIL_NOT_PROVIDED: ClassVar[tuple[str, str]] = (
        N_("Email not provided"),
        "error",
    )
    SECURITY_MSG_INVALID_EMAIL_ADDRESS: ClassVar[tuple[str, str]] = (
        N_("Invalid email address"),
        "error",
    )
    SECURITY_MSG_INVALID_REDIRECT: ClassVar[tuple[str, str]] = (
        N_("Redirections outside the domain are forbidden"),
        "error",
    )

    # The audit log keeps its entries this many days (0 = forever); the worker removes older ones.
    AUDIT_RETENTION_DAYS: int = 730

    # How long a one-time link (an invitation for a new account, a reset for an existing one) works.
    INVITATION_HOURS: int = 72

    # Authentication abuse controls
    AUTH_RATE_LIMIT_KEY: str = ""
    AUTH_RATE_LIMIT_FAILURES: int = 5
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 15 * 60

    # How many reverse proxies stand between the clients and the app. 0 = none: the address of
    # the connection is the client's, and X-Forwarded-* headers are ignored. Behind N proxies that
    # each append to X-Forwarded-For, the N-th entry from the right is the client, which the
    # sign-in rate limit needs to tell clients apart (see docs/deploy.md).
    TRUSTED_PROXY_COUNT: int = 0

    # Database
    SQLALCHEMY_DATABASE_URI: str = ""
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict[str, Any]] = {"pool_pre_ping": True}
    # Empty = the server's default schema. Set it when the role cannot write to `public`
    # (shared servers): `flask db upgrade` creates the schema and the app uses it.
    DB_SCHEMA: str = ""

    # Scanning limits. A scan reviews at most MAX_HOSTS_PER_RUN hosts (never above
    # MAX_HOSTS_CEILING); one person may start MAX_SCANS_PER_USER_PER_HOUR scans an hour
    # (0 = no limit): both keep a stolen session or a careless script from loading the targets,
    # the providers and the worker.
    MAX_HOSTS_PER_RUN: int = 200
    MAX_SCANS_PER_USER_PER_HOUR: int = 20
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

    # Offline IP location data (DB-IP Lite, installed by `flask datasets update`)
    DATASETS_DIR: str = str(Path(__file__).resolve().parents[1] / "var" / "datasets")

    # Rules (docs/rules.md): the countries a host may be located in, and how recent a public breach
    # must be (in months) to count as recent (PUBLIC_BREACH_HISTORY is High, otherwise Medium).
    DATA_LOCATION_ALLOWED: ClassVar[list[str]] = list(DEFAULT_DATA_LOCATION_ALLOWED)
    BREACH_RECENT_MONTHS: int = 24

    # Third-party lookups of the assessed domain (see EXTERNAL_LOOKUP_KEYS); the checks behind a
    # name that is left out report "skipped: disabled" instead of asking: switching a lookup off is
    # a decision, so it neither leaves hosts with gaps nor makes a scan partial.
    EXTERNAL_DOMAIN_LOOKUPS: ClassVar[list[str]] = list(EXTERNAL_LOOKUP_DEFAULTS)

    # Security DNS resolvers asked whether they block a host (see REPUTATION_RESOLVER_KEYS). Every
    # host name of a scan is sent to each of them; a plain DNS question, like the DNS check's.
    REPUTATION_RESOLVERS: ClassVar[list[str]] = list(REPUTATION_RESOLVER_KEYS)

    # Blocklists of malware, phishing and botnet hosts (see BLOCKLIST_PROVIDER_KEYS), downloaded by
    # `flask datasets update` and matched on this machine: nothing about an assessment is sent
    # anywhere. A provider that is left out is neither downloaded nor looked at; URLhaus is not in
    # the default list (see BLOCKLIST_PROVIDER_DEFAULTS).
    BLOCKLIST_PROVIDERS: ClassVar[list[str]] = list(BLOCKLIST_PROVIDER_DEFAULTS)

    # Ports and CVEs that Shodan has observed on a host's addresses. `auto` uses the Shodan host
    # API when SHODAN_API_KEY is set and is off otherwise: the keyless InternetDB is free for
    # non-commercial use only, so it runs only when PORTS_PROVIDER=internetdb asks for it. The
    # rates are requests per second towards each provider (shared by all worker threads); answers
    # are reused for PORTS_CACHE_HOURS per address.
    PORTS_PROVIDER: str = "auto"
    SHODAN_API_KEY: str = ""
    SHODAN_RATE_PER_SECOND: float = 1.0
    INTERNETDB_RATE_PER_SECOND: float = 2.0
    PORTS_CACHE_HOURS: float = 24.0

    # Outgoing requests to public provider APIs
    USER_AGENT: str = "Gaprism/0.1 (+https://github.com/gaprism/gaprism)"
    PROVIDER_TIMEOUT_SECONDS: float = 20.0

    # Anti-SSRF & network settings. The DNS check asks EGRESS_DNS_RESOLVERS (empty list = the
    # system resolver) and waits at most DNS_TIMEOUT_SECONDS per attempt; the TLS and HTTP
    # checks use the two EGRESS_* timeouts.
    EGRESS_DNS_RESOLVERS: ClassVar[list[str]] = ["1.1.1.1", "8.8.8.8"]
    DNS_TIMEOUT_SECONDS: float = 5.0
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


def normalise_database_url(url: str) -> str:
    """Name the driver in the address of a hosted database.

    Neon, Render and the like hand out ``postgres://`` or ``postgresql://`` addresses, which
    SQLAlchemy opens with psycopg2; this project installs psycopg 3. An address that names a
    driver itself is the operator's choice and stays as it is.
    """
    for scheme in ("postgres://", "postgresql://"):
        if url.startswith(scheme):
            return "postgresql+psycopg://" + url[len(scheme) :]
    return url


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

    if not isinstance(max_hosts, int) or isinstance(max_hosts, bool) or max_hosts <= 0:
        raise ConfigurationError("MAX_HOSTS_PER_RUN must be a positive integer.")
    if max_hosts > MAX_HOSTS_CEILING:
        raise ConfigurationError(f"MAX_HOSTS_PER_RUN may not exceed {MAX_HOSTS_CEILING}.")
    for name, ceiling in (
        ("MAX_SCANS_PER_USER_PER_HOUR", MAX_SCANS_PER_HOUR_CEILING),
        ("AUDIT_RETENTION_DAYS", MAX_AUDIT_RETENTION_DAYS),
    ):
        value = getattr(config_obj, name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= ceiling:
            raise ConfigurationError(f"{name} must be an integer from 0 to {ceiling}.")

    if not isinstance(max_pages, int) or max_pages <= 0:
        raise ConfigurationError("MAX_DISCOVERY_PAGES must be a positive integer.")

    for name in ("WORKER_THREADS", "PER_TARGET_CONCURRENCY"):
        value = getattr(config_obj, name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 64:
            raise ConfigurationError(f"{name} must be an integer from 1 to 64.")

    invitation_hours = getattr(config_obj, "INVITATION_HOURS", 0)
    if (
        not isinstance(invitation_hours, int)
        or isinstance(invitation_hours, bool)
        or not 1 <= invitation_hours <= MAX_INVITATION_HOURS
    ):
        raise ConfigurationError(
            f"INVITATION_HOURS must be an integer from 1 to {MAX_INVITATION_HOURS}."
        )

    ct_sources = list(getattr(config_obj, "CT_SOURCES", []))
    unknown_sources = sorted(set(ct_sources) - set(CT_SOURCE_KEYS))
    if not ct_sources or unknown_sources:
        raise ConfigurationError(
            f"CT_SOURCES must list at least one of {', '.join(CT_SOURCE_KEYS)}"
            + (f" (unknown: {', '.join(unknown_sources)})." if unknown_sources else ".")
        )
    if getattr(config_obj, "CT_MODE", "") not in ("union", "first"):
        raise ConfigurationError("CT_MODE must be 'union' or 'first'.")
    allowed = list(getattr(config_obj, "DATA_LOCATION_ALLOWED", []))
    if not allowed or any(not _COUNTRY_CODE.fullmatch(str(code)) for code in allowed):
        raise ConfigurationError(
            "DATA_LOCATION_ALLOWED must list two-letter country codes in capitals, e.g. CH,DE."
        )
    months = getattr(config_obj, "BREACH_RECENT_MONTHS", 0)
    if not isinstance(months, int) or isinstance(months, bool) or not 1 <= months <= 240:
        raise ConfigurationError("BREACH_RECENT_MONTHS must be an integer from 1 to 240.")
    unknown_lookups = sorted(
        set(getattr(config_obj, "EXTERNAL_DOMAIN_LOOKUPS", [])) - set(EXTERNAL_LOOKUP_KEYS)
    )
    if unknown_lookups:
        raise ConfigurationError(
            f"EXTERNAL_DOMAIN_LOOKUPS may list {', '.join(EXTERNAL_LOOKUP_KEYS)} "
            f"(or 'none'); unknown: {', '.join(unknown_lookups)}."
        )
    unknown_resolvers = sorted(
        set(getattr(config_obj, "REPUTATION_RESOLVERS", [])) - set(REPUTATION_RESOLVER_KEYS)
    )
    if unknown_resolvers:
        raise ConfigurationError(
            f"REPUTATION_RESOLVERS may list {', '.join(REPUTATION_RESOLVER_KEYS)} "
            f"(or 'none'); unknown: {', '.join(unknown_resolvers)}."
        )
    unknown_blocklists = sorted(
        set(getattr(config_obj, "BLOCKLIST_PROVIDERS", [])) - set(BLOCKLIST_PROVIDER_KEYS)
    )
    if unknown_blocklists:
        raise ConfigurationError(
            f"BLOCKLIST_PROVIDERS may list {', '.join(BLOCKLIST_PROVIDER_KEYS)} "
            f"(or 'none'); unknown: {', '.join(unknown_blocklists)}."
        )
    if getattr(config_obj, "PORTS_PROVIDER", "") not in PORTS_PROVIDERS:
        raise ConfigurationError(f"PORTS_PROVIDER must be one of {', '.join(PORTS_PROVIDERS)}.")
    for name in (
        "PROVIDER_TIMEOUT_SECONDS",
        "DISCOVERY_BUDGET_SECONDS",
        "DNS_TIMEOUT_SECONDS",
        "EGRESS_CONNECT_TIMEOUT_SEC",
        "EGRESS_READ_TIMEOUT_SEC",
        "SHODAN_RATE_PER_SECOND",
        "INTERNETDB_RATE_PER_SECOND",
        "PORTS_CACHE_HOURS",
    ):
        number = getattr(config_obj, name, 0)
        if (
            not isinstance(number, int | float)
            or isinstance(number, bool)
            or not math.isfinite(number)
            or number <= 0
        ):
            raise ConfigurationError(f"{name} must be a positive number.")
    if getattr(config_obj, "PORTS_CACHE_HOURS", 0) > MAX_PORTS_CACHE_HOURS:
        raise ConfigurationError(f"PORTS_CACHE_HOURS must not exceed {MAX_PORTS_CACHE_HOURS}.")
    for resolver in getattr(config_obj, "EGRESS_DNS_RESOLVERS", []):
        try:
            ipaddress.ip_address(str(resolver))
        except ValueError as exc:
            raise ConfigurationError(
                "EGRESS_DNS_RESOLVERS must list IP addresses (or 'system' for the system resolver)."
            ) from exc

    proxies = getattr(config_obj, "TRUSTED_PROXY_COUNT", 0)
    if (
        not isinstance(proxies, int)
        or isinstance(proxies, bool)
        or not 0 <= proxies <= MAX_TRUSTED_PROXIES
    ):
        raise ConfigurationError(
            f"TRUSTED_PROXY_COUNT must be an integer from 0 to {MAX_TRUSTED_PROXIES}."
        )

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
            "TRUSTED_PROXY_COUNT": "TRUSTED_PROXY_COUNT",
            "SQLALCHEMY_DATABASE_URI": "TEST_DATABASE_URL"
            if config_class.TESTING
            else "DATABASE_URL",
            "DB_SCHEMA": "DB_SCHEMA",
            "REQUIRE_MFA": "REQUIRE_MFA",
            "MAX_HOSTS_PER_RUN": "MAX_HOSTS_PER_RUN",
            "MAX_SCANS_PER_USER_PER_HOUR": "MAX_SCANS_PER_USER_PER_HOUR",
            "AUDIT_RETENTION_DAYS": "AUDIT_RETENTION_DAYS",
            "INVITATION_HOURS": "INVITATION_HOURS",
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
            "DATASETS_DIR": "DATASETS_DIR",
            "DATA_LOCATION_ALLOWED": "DATA_LOCATION_ALLOWED",
            "BREACH_RECENT_MONTHS": "BREACH_RECENT_MONTHS",
            "EXTERNAL_DOMAIN_LOOKUPS": "EXTERNAL_DOMAIN_LOOKUPS",
            "REPUTATION_RESOLVERS": "REPUTATION_RESOLVERS",
            "BLOCKLIST_PROVIDERS": "BLOCKLIST_PROVIDERS",
            "PORTS_PROVIDER": "PORTS_PROVIDER",
            "SHODAN_API_KEY": "SHODAN_API_KEY",
            "SHODAN_RATE_PER_SECOND": "SHODAN_RATE_PER_SECOND",
            "INTERNETDB_RATE_PER_SECOND": "INTERNETDB_RATE_PER_SECOND",
            "PORTS_CACHE_HOURS": "PORTS_CACHE_HOURS",
            "EGRESS_DNS_RESOLVERS": "EGRESS_DNS_RESOLVERS",
            "DNS_TIMEOUT_SECONDS": "DNS_TIMEOUT_SECONDS",
            "EGRESS_CONNECT_TIMEOUT_SEC": "EGRESS_CONNECT_TIMEOUT_SEC",
            "EGRESS_READ_TIMEOUT_SEC": "EGRESS_READ_TIMEOUT_SEC",
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
            elif key == "SQLALCHEMY_DATABASE_URI":
                values[key] = normalise_database_url(raw.strip())  # pasted values carry spaces
            else:
                values[key] = raw
        if values["EGRESS_DNS_RESOLVERS"] == ["system"]:
            values["EGRESS_DNS_RESOLVERS"] = []  # an empty line cannot say "no resolver list"
        values["DATA_LOCATION_ALLOWED"] = [c.upper() for c in values["DATA_LOCATION_ALLOWED"]]
        if values["EXTERNAL_DOMAIN_LOOKUPS"] == ["none"]:
            values["EXTERNAL_DOMAIN_LOOKUPS"] = []  # an empty line cannot say "none"
        if values["REPUTATION_RESOLVERS"] == ["none"]:
            values["REPUTATION_RESOLVERS"] = []
        if values["BLOCKLIST_PROVIDERS"] == ["none"]:
            values["BLOCKLIST_PROVIDERS"] = []
        values["PORTS_PROVIDER"] = str(values["PORTS_PROVIDER"]).strip().lower()
        values["SHODAN_API_KEY"] = str(values["SHODAN_API_KEY"]).strip()
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
