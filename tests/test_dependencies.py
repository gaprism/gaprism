"""The declared dependencies are the ones the code imports, and the exceptions say why.

What the application imports must be declared (a package that arrives only because another one
needs it can vanish with it), and a runtime dependency nobody imports must be listed here with its
reason, so that the lock does not grow by forgetting.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

from tests.helpers import PROJECT_ROOT

FIRST_PARTY = {"app", "runner", "tests", "scripts", "migrations"}
RUNTIME_CODE = ("app", "runner", "migrations")  # what runs in a deployment
SUPPORT_CODE = ("tests", "scripts")  # what builds and checks it

# Runtime dependencies that are needed without being imported by our own code.
NEEDED_WITHOUT_IMPORT = {
    "psycopg": "the driver SQLAlchemy loads for postgresql+psycopg:// URLs",
    "argon2-cffi": "the password hash Flask-Security is configured with (argon2)",
    "qrcode": "Flask-Security refuses to start with two-factor on and no qrcode",
    "python-dotenv": "`flask` loads .env with it; the tests read the same file",
}


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_names(specs: list[str]) -> set[str]:
    return {normalise(re.split(r"[<>=!~\[ ;]", spec, maxsplit=1)[0]) for spec in specs}


def declared() -> tuple[set[str], set[str], set[str]]:
    """Runtime, development and optional-extra dependencies of pyproject.toml."""
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = requirement_names(data["project"]["dependencies"])
    dev = requirement_names(data["dependency-groups"]["dev"])
    extras = {
        name for specs in data["project"].get("optional-dependencies", {}).values()
        for name in requirement_names(specs)
    }  # fmt: skip
    return runtime, dev, extras


def imported_distributions(folders: tuple[str, ...]) -> dict[str, set[str]]:
    """The installed distributions the code in ``folders`` imports, with the files that do."""
    owners = packages_distributions()
    found: dict[str, set[str]] = {}
    for folder in folders:
        for path in sorted((PROJECT_ROOT / folder).rglob("*.py")):
            for module in top_level_imports(path):
                if module in sys.stdlib_module_names or module in FIRST_PARTY:
                    continue
                for owner in owners.get(module, []):
                    found.setdefault(normalise(owner), set()).add(
                        path.relative_to(PROJECT_ROOT).as_posix()
                    )
    return found


def top_level_imports(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules - {"__future__"}


def test_what_the_application_imports_is_declared_as_a_runtime_dependency() -> None:
    runtime, _, extras = declared()
    missing = {
        name: sorted(files)[:3]
        for name, files in imported_distributions(RUNTIME_CODE).items()
        if name not in runtime | extras
    }
    assert not missing, f"imported but not declared in [project].dependencies: {missing}"


def test_what_the_tests_and_scripts_import_is_declared_somewhere() -> None:
    runtime, dev, extras = declared()
    missing = {
        name: sorted(files)[:3]
        for name, files in imported_distributions(SUPPORT_CODE).items()
        if name not in runtime | dev | extras | {"pytest"}
    }
    assert not missing, f"imported by tests or scripts but not declared: {missing}"


def test_a_runtime_dependency_nobody_imports_is_listed_with_its_reason() -> None:
    runtime, _, _ = declared()
    used = set(imported_distributions(RUNTIME_CODE))
    unused = runtime - used - set(NEEDED_WITHOUT_IMPORT)
    assert not unused, f"declared, never imported, and no reason given: {sorted(unused)}"


def test_the_reasons_listed_here_still_apply() -> None:
    runtime, _, _ = declared()
    used = set(imported_distributions(RUNTIME_CODE))
    stale = {
        name for name in NEEDED_WITHOUT_IMPORT
        if name not in runtime or name in used
    }  # fmt: skip
    assert not stale, (
        f"no longer an unimported runtime dependency (remove from the list): {sorted(stale)}"
    )


def test_the_development_tools_stay_out_of_the_runtime_dependencies() -> None:
    runtime, dev, _ = declared()
    assert not runtime & dev, f"in both lists: {sorted(runtime & dev)}"
    assert not {"pytest", "ruff", "mypy", "pip-audit", "pyotp"} & runtime
