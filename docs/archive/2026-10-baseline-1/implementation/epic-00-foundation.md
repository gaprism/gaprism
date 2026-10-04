# Epic 00: Project Foundation & Test Harness (Milestone M0)

**Epic Owner**: Core Platform Architecture  
**Target Milestone**: M0 Foundation  
**Status**: Implemented and verified (2026-10-02)  
**Key Invariants Enforced**: INV-12 (No network work, scheduler, or migration starts as an import-time side effect)

---

## 1. Epic Overview

The objective of Epic 00 is to construct the modular Flask application skeleton, structured configuration validation, database extension bindings, and a PostgreSQL test container fixture harness. It ensures that two application instances can be instantiated simultaneously with independent configurations, without import-time side effects, and with reproducible developer and CI test runs.

---

## 2. Stories Breakdown

### Story 0.1: Application Factory & Centralised Configuration
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Configuration isolation and fail-safe startup need strong cross-file reasoning, but the contracts are explicit enough that Astra is not cost-effective as the default.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) only if framework lifecycle behaviour remains ambiguous after focused tests.
- **Goal**: Implement `create_app()` factory, environment configuration profiles, and fail-fast startup configuration validation.
- **Invariants Enforced**: INV-12
- **Technical Contracts**:
  - `app/config.py`:
    - `BaseConfig`: shared settings (`SECRET_KEY`, `SQLALCHEMY_TRACK_MODIFICATIONS = False`, `WTF_CSRF_ENABLED = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`).
    - `DevelopmentConfig`, `TestingConfig`, `ProductionConfig`.
    - `validate_config(config: BaseConfig) -> None`: Raises `ConfigurationError` on missing critical keys (e.g., missing database URI, empty secrets in production, invalid directory paths).
  - `app/__init__.py`:
    - `create_app(config_object: str | type[BaseConfig] | None = None) -> Flask`: Binds extensions, registers Blueprints, configures error handlers, and avoids global state mutations.
- **Acceptance Criteria**:
  - Instantiating `create_app()` twice generates independent application contexts with distinct configurations.
  - Importing `app` or any sub-module performs zero network calls, database queries, or worker spawns.
  - Running in production mode with a weak or default `SECRET_KEY` aborts startup immediately with a non-zero exit code.
- **Definition of Done (DoD)**:
  - [x] `app/config.py` and `app/__init__.py` implemented.
  - [x] Unit tests in `tests/test_factory.py` asserting independent instances and configuration validation errors.
  - [x] Strict type checking passes (`mypy --strict app/`).
  - [x] Zero linter violations (`ruff check .`).

---

### Story 0.2: Extension Wiring & Database Fixtures
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: PostgreSQL migrations, transactional fixtures, and extension lifecycle are coupled integration work where Sol offers the best quality/cost balance.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if migration or connection-pool behaviour conflicts across environments.
- **Goal**: Initialize SQLAlchemy, Flask-Migrate (Alembic), Flask-WTF, and Flask-Security-Too extensions, and establish a disposable PostgreSQL test harness.
- **Invariants Enforced**: INV-12
- **Technical Contracts**:
  - `app/extensions.py`:
    - Declarations of unbound extensions: `db = SQLAlchemy()`, `migrate = Migrate()`, `csrf = CSRFProtect()`, `security = Security()`.
    - Extensions attached inside `create_app()` via `init_app(app)`.
  - `tests/conftest.py`:
    - Pytest fixture `db_session` providing transactional rollback isolation per test.
    - PostgreSQL test container integration (or disposable PostgreSQL URL fixture) to execute full migrations and ensure dialect compatibility.
    - SQLite is explicitly disallowed for PostgreSQL-specific constraint or RLS testing.
- **Acceptance Criteria**:
  - `flask db upgrade` executes cleanly on an empty PostgreSQL database.
  - Pytest fixtures start up clean test schemas and roll back transactions after each test run.
  - No database connection is initiated at module import time.
- **Definition of Done (DoD)**:
  - [x] `app/extensions.py` and `tests/conftest.py` implemented.
  - [x] Migration baseline generated in `migrations/`.
  - [x] Migration rollback and upgrade tests passing in `tests/test_migrations.py`.
  - [x] Type checks pass (`mypy --strict app/ tests/`).

---

### Story 0.3: Tooling, Linting & Type Checking Baseline
- **Coding-agent model**: `gpt-6-luna` with reasoning effort `high`.
- **Price/performance rationale**: Dependency locking and lint/type configuration are bounded, tool-verifiable changes; Luna is sufficient when given the exact commands and acceptance gates.
- **Escalation rule**: Escalate to `gpt-6.1-sol` (`medium`) only for dependency-resolution or typing conflicts spanning several libraries.
- **Goal**: Establish project dependency locking, linting, formatting, and strict type checking configurations in `pyproject.toml`.
- **Invariants Enforced**: INV-12
- **Technical Contracts**:
  - `pyproject.toml`:
    - Python requirement: `>=3.11`.
    - Direct runtime dependencies locked: `Flask`, `Flask-SQLAlchemy`, `SQLAlchemy`, `psycopg[binary]`, `Flask-Migrate`, `alembic`, `Flask-Security-Too`, `Flask-WTF`, `cryptography`, `pydantic`, `httpx`, `playwright`, `jinja2`, `babel`.
    - Development dependencies: `pytest`, `pytest-cov`, `pytest-playwright`, `ruff`, `mypy`, `testcontainers[postgres]`.
    - Ruff configuration: enforce PEP 8, flake8 rules, import sorting (`isort`), and docstring checks.
    - Mypy configuration: `strict = true`, `disallow_untyped_defs = true`, `disallow_any_generics = true`.
- **Acceptance Criteria**:
  - Running `ruff check .` passes without errors.
  - Running `mypy --strict app` passes with 0 type errors.
  - Running `pytest` discovers and executes the test harness cleanly.
- **Definition of Done (DoD)**:
  - [x] `pyproject.toml` configured and validated.
  - [x] All development tools run cleanly from local CLI.

### Verification evidence

Verified on 2026-10-02 against a generated disposable PostgreSQL database:

- `pytest`: 165 tests passed, including empty-database upgrade, downgrade to `base`, and re-upgrade.
- `mypy --strict app tests`: no issues in 63 source files.
- `mypy --strict app runner`: no issues in 41 source files.
- `ruff check --no-cache .`: no violations.
- Factory tests cover independent configuration, invalid configuration, weak production secrets,
  invalid storage paths, and a subprocess import-side-effect probe.
