"""The deployment files (Dockerfile, docker-compose.yml, .env.example) keep their promises.

No Docker is needed: these read the files as text. They guard what a typo would break quietly:
a secret ending up in an image, a database port on the host, a setting nobody documented.
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path

import pytest
from dotenv import dotenv_values

from app import create_app
from app.config import BLOCKLIST_PROVIDER_DEFAULTS

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
ENV_EXAMPLE = ROOT / ".env.example"


def lines_of(path: Path) -> list[str]:
    """The lines of a file that say something (no blanks, no comments)."""
    stripped = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in stripped if line and not line.startswith("#")]


def service(name: str) -> str:
    """The text of one service of docker-compose.yml, up to the next top-level entry."""
    found = re.search(rf"^  {name}:\n(.*?)(?=^  \S|^\S|\Z)", COMPOSE, re.MULTILINE | re.DOTALL)
    assert found, f"no service {name}"
    return found.group(1)


# ------------------------------------------------------------------------------ images


def test_secrets_and_local_data_never_enter_the_build_context() -> None:
    ignored = lines_of(ROOT / ".dockerignore")
    for pattern in (".env", ".env.*", "var", ".git", ".venv", "node_modules"):
        assert pattern in ignored, pattern
    assert ignored.index("!.env.example") > ignored.index(".env.*")  # the template, nothing else


def test_the_dockerfile_copies_named_paths_and_never_the_settings() -> None:
    copies = re.findall(r"^COPY\s+(?:--\S+\s+)*(.+)$", DOCKERFILE, re.MULTILINE)
    assert copies
    for source in copies:
        assert not re.match(r"\.\s", source), f"copies the whole context: {source}"
        assert ".env" not in source, source


def test_the_image_gets_every_package_the_application_imports() -> None:
    """A package the Dockerfile forgot to copy would fail only inside the image."""
    from_context = [
        source.split()[0]
        for line in DOCKERFILE.splitlines()
        if line.startswith("COPY ") and "--from=" not in line
        for source in [line.removeprefix("COPY ").rsplit(" ", 1)[0]]
    ]
    copied = {Path(source).parts[0] for source in from_context}
    for source in from_context:
        assert (ROOT / source).exists(), f"the Dockerfile copies {source}, which does not exist"
    packages = {
        path.parent.name
        for path in ROOT.glob("*/__init__.py")
        if path.parent.name not in {"tests", "docs", "scripts", "assets"}
    }
    assert packages <= copied, sorted(packages - copied)  # app and runner
    assert {"migrations", "app", "runner"} <= copied


def test_the_image_runs_as_an_unprivileged_user() -> None:
    final = DOCKERFILE.rsplit("\nFROM ", 1)[1]
    assert re.search(r"^USER app$", final, re.MULTILINE)
    assert "useradd" in final and "--uid 10001" in final
    assert final.count("CMD [") == 1 and '"gunicorn"' in final


def test_gunicorn_is_installed_from_the_lock_file() -> None:
    assert "uv sync --frozen --no-dev --group deploy" in DOCKERFILE
    assert re.search(
        r'^deploy = \[\s*"gunicorn', (ROOT / "pyproject.toml").read_text("utf-8"), re.M
    )


# ------------------------------------------------------------------------------ compose


def test_every_setting_compose_reads_is_documented_in_the_example() -> None:
    names = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", COMPOSE))
    assert {"POSTGRES_PASSWORD", "WEB_PORT", "SITE_ADDRESS"} <= names
    documented = {
        match.group(1)
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if (match := re.match(r"#?\s*([A-Z][A-Z0-9_]*)=", line))
    }
    assert names <= documented, sorted(names - documented)


def test_the_database_is_reachable_only_from_the_application_networks() -> None:
    database = service("db")
    assert "ports:" not in database  # nothing on the host
    assert re.search(r"networks: \[backend\]", database)  # and no way to the internet
    assert re.search(r"^  backend:\n    internal: true", COMPOSE, re.MULTILINE)
    for name in ("migrate", "web", "worker", "cli"):
        assert "ports:" not in service(name) or name == "web"


def test_application_containers_are_locked_down() -> None:
    shared = COMPOSE.split("\nservices:\n", 1)[0]  # the x-app block every service starts from
    assert "read_only: true" in shared
    assert "cap_drop: [ALL]" in shared
    assert "no-new-privileges:true" in shared
    assert "privileged" not in COMPOSE and "docker.sock" not in COMPOSE
    for name in ("migrate", "web", "worker", "cli"):
        assert "<<: *app" in service(name), name


def test_the_web_app_listens_on_the_loopback_interface_unless_told_otherwise() -> None:
    assert '"${WEB_BIND:-127.0.0.1}:${WEB_PORT:-8080}:8000"' in service("web")


def test_the_application_starts_only_after_the_schema_is_current() -> None:
    for name in ("web", "worker", "cli"):
        assert "condition: service_completed_successfully" in service(name), name
    assert "condition: service_healthy" in service("migrate")  # the database answers first


def test_the_proxy_is_optional_and_forwards_to_the_web_app() -> None:
    assert "profiles: [proxy]" in service("proxy")
    caddyfile = lines_of(ROOT / "deploy" / "Caddyfile")
    assert "reverse_proxy web:8000" in caddyfile
    assert caddyfile[0].startswith("{$SITE_ADDRESS:localhost}")


# ------------------------------------------------------------------------------ settings


def load_example(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {k: v for k, v in dotenv_values(ENV_EXAMPLE).items() if v is not None}
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


def test_the_example_settings_are_accepted_for_development(monkeypatch: pytest.MonkeyPatch) -> None:
    values = load_example(monkeypatch)
    app = create_app("development")  # empty lines mean "not set"; nothing may be rejected
    assert app.config["TRUSTED_PROXY_COUNT"] == int(values["TRUSTED_PROXY_COUNT"]) == 0


def test_a_copy_of_the_example_leaves_the_sources_with_terms_to_decide_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """InternetDB (non-commercial) and URLhaus (fair use) are opt-in, also from the template."""
    values = load_example(monkeypatch)
    assert values["PORTS_PROVIDER"] == "auto" and not values.get("SHODAN_API_KEY")
    assert values["BLOCKLIST_PROVIDERS"].split(",") == list(BLOCKLIST_PROVIDER_DEFAULTS)
    config = create_app("development").config
    assert config["PORTS_PROVIDER"] == "auto" and "urlhaus" not in config["BLOCKLIST_PROVIDERS"]


def test_the_quickstart_secrets_pass_the_production_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """`openssl rand -hex 32` for each of the four secrets: hex cannot spell a rejected word."""
    load_example(monkeypatch)
    for name in (
        "SECRET_KEY",
        "SECURITY_PASSWORD_SALT",
        "MFA_ENCRYPTION_KEY",
        "AUTH_RATE_LIMIT_KEY",
    ):
        monkeypatch.setenv(name, secrets.token_hex(32))
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://due_diligence:abc@db:5432/due_diligence"
    )
    app = create_app("production")
    assert app.config["ENV"] == "production" and app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["REQUIRE_MFA"] is True  # the example does not switch it off
