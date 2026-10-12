"""The Render Blueprint and its start command keep their promises.

No Render account and no Docker are needed: these read the files as text, like test_deploy_kit.py.
They guard what a typo would break quietly: a secret written into the repository, a setting the
application does not know, values that production would reject at the first start, a start
command that drifted away from the image's.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from pathlib import Path

import pytest

from app import create_app
from app.service.discovery.scope import is_in_scope

ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT = (ROOT / "render.yaml").read_text(encoding="utf-8")
START = (ROOT / "deploy" / "render-start.sh").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")

SECRETS = ("SECRET_KEY", "SECURITY_PASSWORD_SALT", "MFA_ENCRYPTION_KEY", "AUTH_RATE_LIMIT_KEY")
# What Neon hands out for a project (the direct connection; the host has no "-pooler").
NEON_ADDRESS = (
    "postgresql://demo_owner:not-a-password@ep-quiet-sun-123456.eu-central-1.aws.neon.tech/"
    "demo?sslmode=require&channel_binding=require"
)


def service_settings() -> dict[str, str]:
    """The plain `key: value` lines of the one service, above its environment variables."""
    head = BLUEPRINT.split("    envVars:\n", 1)[0]
    found = re.findall(r"^(?:  - |    )(\w+): (.+?)(?:\s+#.*)?$", head, re.MULTILINE)
    return {key: value.strip('"') for key, value in found}


def environment() -> dict[str, tuple[str, str]]:
    """Name -> (how it is given, what is given): `value`, `generateValue` or `sync`."""
    found = re.findall(
        r"^      - key: (\w+)\n        (value|generateValue|sync): (.+?)(?:\s+#.*)?$",
        BLUEPRINT,
        re.MULTILINE,
    )
    assert len(found) == BLUEPRINT.count("- key: "), "an environment variable the test cannot read"
    return {name: (kind, value.strip('"')) for name, kind, value in found}


def stand_in(name: str) -> str:
    """Like Render's generated values: base64 of 256 bits (with + / = in it), the same each run."""
    return base64.b64encode(hashlib.sha256(f"stand-in for {name}".encode()).digest()).decode()


# ------------------------------------------------------------------------------ the Blueprint


def test_the_blueprint_is_one_free_docker_web_service() -> None:
    service = service_settings()
    assert BLUEPRINT.count("\n  - type: ") == 1  # no worker, no database: not free, or not for long
    assert not re.search(r"^(databases|envVarGroups):", BLUEPRINT, re.MULTILINE)
    assert (service["type"], service["runtime"], service["plan"]) == ("web", "docker", "free")
    assert service["region"] == "frankfurt"
    assert service["healthCheckPath"] == "/healthz"
    assert service["autoDeployTrigger"] == "off"  # peers never see a half-finished commit


def test_the_blueprint_holds_no_secret_and_no_provider_key() -> None:
    variables = environment()
    assert variables["DATABASE_URL"] == ("sync", "false")  # asked for, never written here
    for name in SECRETS:
        assert variables[name] == ("generateValue", "true"), name
    for name, (kind, value) in variables.items():
        if kind != "value":
            continue
        assert "://" not in value and "@" not in value, f"{name} looks like an address"
        assert not re.search(r"KEY|TOKEN|SALT|PASSWORD|SECRET", name), f"{name} is a secret"
    assert not {"SHODAN_API_KEY", "CTLOGS_API_KEY", "CERTSPOTTER_TOKEN"} & set(variables)


def test_every_setting_of_the_blueprint_is_one_the_application_or_the_image_reads() -> None:
    documented = {
        match.group(1)
        for line in ENV_EXAMPLE.splitlines()
        if (match := re.match(r"#?\s*([A-Z][A-Z0-9_]*)=", line))
    }
    in_the_image = set(re.findall(r"^(?:ARG|ENV)?\s+([A-Z][A-Z0-9_]*)=", DOCKERFILE, re.MULTILINE))
    in_the_image |= set(re.findall(r"^ARG\s+([A-Z][A-Z0-9_]*)", DOCKERFILE, re.MULTILINE))
    unknown = set(environment()) - documented - in_the_image
    assert not unknown, sorted(unknown)


def test_the_values_of_the_blueprint_start_the_application_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What Render would hand the container: its values, its generated secrets, Neon's address."""
    for name, (kind, value) in environment().items():
        if kind == "value":
            monkeypatch.setenv(name, value)
        elif kind == "generateValue":
            monkeypatch.setenv(name, stand_in(name))
    monkeypatch.setenv("DATABASE_URL", NEON_ADDRESS)
    monkeypatch.setenv("DB_SCHEMA", "")
    for name in ("SHODAN_API_KEY", "CTLOGS_API_KEY", "CERTSPOTTER_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    config = create_app("production").config

    assert config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql+psycopg://demo_owner:")
    assert config["SQLALCHEMY_DATABASE_URI"].endswith("?sslmode=require&channel_binding=require")
    assert config["REQUIRE_MFA"] is True and config["SESSION_COOKIE_SECURE"] is True
    assert config["TRUSTED_PROXY_COUNT"] == 1
    assert (config["MAX_HOSTS_PER_RUN"], config["MAX_SCANS_PER_USER_PER_HOUR"]) == (30, 10)
    assert (config["WORKER_THREADS"], config["PER_TARGET_CONCURRENCY"]) == (2, 2)
    # Render hosts other people's services: its names are not scan targets.
    assert is_in_scope("demo.onrender.com", "onrender.com")
    assert {"render.com", "onrender.com"} <= set(config["BLOCKED_DOMAINS"])
    # The sources with terms to decide stay off: no key, no InternetDB, no URLhaus.
    assert config["PORTS_PROVIDER"] == "auto" and not config["SHODAN_API_KEY"]
    assert "urlhaus" not in config["BLOCKLIST_PROVIDERS"]


def test_the_documentation_says_what_the_blueprint_sets() -> None:
    """The guide names the service and the limits the testers are told about."""
    guide = (ROOT / "docs" / "deploy-render.md").read_text(encoding="utf-8")
    variables = environment()
    assert service_settings()["name"] in guide
    assert f"{variables['MAX_HOSTS_PER_RUN'][1]} hosts per scan" in guide
    assert f"{variables['MAX_SCANS_PER_USER_PER_HOUR'][1]} scans per hour" in guide
    for blocked in variables["BLOCKED_DOMAINS"][1].split(","):
        assert f"`{blocked}`" in guide
    assert "deploy/render-start.sh" in guide and "BAKE_DATASETS" in guide


# ------------------------------------------------------------------------------ the container


def image_command() -> list[str]:
    """The CMD of the image, as the list Docker would run."""
    final = DOCKERFILE.rsplit("\nFROM ", 1)[1]
    found = re.search(r"^CMD (\[.*?\])\s*$", final, re.MULTILINE | re.DOTALL)
    assert found, "the Dockerfile has no CMD in exec form"
    command = json.loads(found.group(1).replace("\\\n", ""))
    assert isinstance(command, list)
    return [str(part) for part in command]


def started_command() -> list[str]:
    """The gunicorn command line of the start script."""
    lines = START.splitlines()
    first = next(i for i, line in enumerate(lines) if line.startswith("exec gunicorn"))
    joined = []
    for line in lines[first:]:
        joined.append(line.removesuffix("\\"))
        if not line.endswith("\\"):
            break
    return shlex.split(" ".join(joined))[1:]  # without "exec"


def without_bind(command: list[str]) -> list[str]:
    at = command.index("--bind")
    return command[:at] + command[at + 2 :]


def test_the_start_script_serves_with_the_same_settings_as_the_image() -> None:
    """Only the port differs (Render says which); the access log must keep query strings out."""
    started, image = started_command(), image_command()
    assert started[started.index("--bind") + 1] == "0.0.0.0:${PORT:-8000}"
    assert without_bind(started) == without_bind(image)
    assert '"%(m)s %(U)s"' in " ".join(image)  # the path, not the query string


def test_the_start_script_migrates_first_runs_the_worker_and_hands_over_to_the_server() -> None:
    assert START.startswith("#!/bin/sh\n") and "\nset -eu\n" in START
    migrate, worker, serve = (
        START.index("until flask db upgrade; do\n"),
        START.index("flask worker ||"),
        START.index("exec gunicorn "),
    )
    assert migrate < worker < serve  # the schema first, the server last (it becomes process 1)
    assert re.search(r"while true; do\s+flask worker \|\|.*\n\s+sleep \d+\s+done\n\) &", START)


def test_the_blueprint_starts_the_script_the_image_carries() -> None:
    command = service_settings()["dockerCommand"]
    assert command == "sh /app/deploy/render-start.sh"
    assert "COPY deploy/render-start.sh ./deploy/render-start.sh" in DOCKERFILE
    assert "WORKDIR /app" in DOCKERFILE


def test_the_image_installs_data_only_when_the_build_asks_for_it() -> None:
    """Compose builds without arguments; Render passes BAKE_DATASETS from the Blueprint."""
    assert re.search(r"^ARG BAKE_DATASETS=0$", DOCKERFILE, re.MULTILINE)
    assert re.search(r"^ARG BLOCKLIST_PROVIDERS$", DOCKERFILE, re.MULTILINE)  # the build follows
    assert environment()["BAKE_DATASETS"] == ("value", "1")
    run = re.search(r'^RUN if \[ "\$BAKE_DATASETS" = "1" \]; then (.+); fi$', DOCKERFILE, re.M)
    assert run and run.group(1).endswith("flask datasets update")
    assert DOCKERFILE.index("\nUSER app\n") < run.start()  # not as root
