"""The licences of everything the lock installs: an allowlist, one reviewed exception, no surprises.

The project is Apache-2.0 and promises to stay open. Whatever it ships with has to allow that, so
every package in ``uv.lock`` (runtime, deployment, optional and development, 84 today) is listed
below with the licence it was checked to have, and the test refuses

- a package that is in the lock but not in the table (add it after reading its licence),
- a licence that is not on the allowlist (Apache-2.0, MIT, BSD, ISC, PSF, MPL-2.0 and public-domain
  style licences; GPL and AGPL never; LGPL only as a reviewed exception),
- an installed package whose own metadata says something else than the table (it changed licence
  upstream: read the new one), and
- table entries for packages that are no longer in the lock.

The table, not the metadata alone, decides, because the metadata of a package that is not installed
here (another platform, another Python, the deployment group, the optional extras) is not there to
read, and CI must give the same answer as a developer's machine.
"""

from __future__ import annotations

import re
import tomllib
from importlib import metadata
from importlib.metadata import PackageNotFoundError

import pytest

from tests.helpers import PROJECT_ROOT

# Package -> its licence as an SPDX expression. Checked 2026-10-11: from the metadata of the
# installed package where there is one; for greenlet, gunicorn, playwright and pyee (not installed
# on every machine) from the metadata of the locked release on PyPI.
LICENCES = {
    "alembic": "MIT",
    "anyio": "MIT",
    "argon2-cffi": "MIT",
    "argon2-cffi-bindings": "MIT",
    "ast-serialize": "MIT",
    "babel": "BSD-3-Clause",
    "blinker": "MIT",
    "boolean-py": "BSD-2-Clause",
    "cachecontrol": "Apache-2.0",
    "certifi": "MPL-2.0",
    "cffi": "MIT-0",
    "charset-normalizer": "MIT",
    "click": "BSD-3-Clause",
    "colorama": "BSD-3-Clause",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "cyclonedx-python-lib": "Apache-2.0",
    "defusedxml": "PSF-2.0",
    "dnspython": "ISC",
    "email-validator": "Unlicense",
    "filelock": "MIT",
    "flask": "BSD-3-Clause",
    "flask-login": "MIT",
    "flask-migrate": "MIT",
    "flask-principal": "MIT",
    "flask-security-too": "MIT",
    "flask-sqlalchemy": "BSD",
    "flask-wtf": "BSD-3-Clause",
    "greenlet": "MIT AND PSF-2.0",
    "gunicorn": "MIT",
    "h11": "MIT",
    "httpcore": "BSD-3-Clause",
    "httpx": "BSD-3-Clause",
    "idna": "BSD-3-Clause",
    "iniconfig": "MIT",
    "itsdangerous": "BSD",
    "jinja2": "BSD",
    "libpass": "BSD",
    "librt": "MIT",
    "license-expression": "Apache-2.0",
    "mako": "MIT",
    "markdown-it-py": "MIT",
    "markupsafe": "BSD-3-Clause",
    "maxminddb": "Apache-2.0",
    "mdurl": "MIT",
    "mmdb-writer": "MIT",
    "msgpack": "Apache-2.0",
    "mypy": "MIT",
    "mypy-extensions": "MIT",
    "netaddr": "BSD",
    "packageurl-python": "MIT",
    "packaging": "Apache-2.0 OR BSD-2-Clause",
    "pathspec": "MPL-2.0",
    "pip": "MIT",
    "pip-api": "Apache-2.0",
    "pip-audit": "Apache-2.0",
    "pillow": "MIT-CMU",
    "pip-requirements-parser": "MIT",
    "platformdirs": "MIT",
    "playwright": "Apache-2.0",
    "pluggy": "MIT",
    "psycopg": "LGPL-3.0-only",
    "psycopg-binary": "LGPL-3.0-only",
    "publicsuffixlist": "MPL-2.0",
    "py-serializable": "Apache-2.0",
    "pycparser": "BSD-3-Clause",
    "pyee": "MIT",
    "pygments": "BSD-2-Clause",
    "pyotp": "MIT",
    "pyparsing": "MIT",
    "pytest": "MIT",
    "python-dotenv": "BSD-3-Clause",
    "qrcode": "BSD",
    "requests": "Apache-2.0",
    "rich": "MIT",
    "ruff": "MIT",
    "sortedcontainers": "Apache-2.0",
    "sqlalchemy": "MIT",
    "tomli": "MIT",
    "tomli-w": "MIT",
    "typing-extensions": "PSF-2.0",
    "tzdata": "Apache-2.0",
    "urllib3": "MIT",
    "werkzeug": "BSD-3-Clause",
    "wtforms": "BSD-3-Clause",
}

# Licences that are not on the allowlist, accepted for one package each, with the reason.
REVIEWED = {
    "psycopg": (
        "LGPL-3.0-only",
        "The database driver, used as an unmodified library (the LGPL allows that; NOTICE says "
        "so). Counsel confirms it at the release review.",
    ),
    "psycopg-binary": (
        "LGPL-3.0-only",
        "The compiled part of the same driver: the same reasoning applies.",
    ),
}

ALLOWED_FAMILIES = {"apache", "mit", "bsd", "isc", "psf", "mpl", "public-domain"}

# What a package may call its licence when it does not use an SPDX expression (lower case).
ALIASES = {
    "mit": "MIT",
    "mit license": "MIT",
    "mit-0": "MIT-0",
    "bsd": "BSD",
    "bsd license": "BSD",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc": "ISC",
    "isc license (iscl)": "ISC",
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "psf-2.0": "PSF-2.0",
    "psfl": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "unlicense": "Unlicense",
    "the unlicense (unlicense)": "Unlicense",
    "lgpl-3.0-only": "LGPL-3.0-only",
}


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def family(licence: str) -> str:
    """The family of one licence id: what the allowlist is about."""
    text = licence.strip().lower()
    for prefix, name in (
        ("apache", "apache"),
        ("mit", "mit"),
        ("bsd", "bsd"),
        ("0bsd", "bsd"),
        ("isc", "isc"),
        ("psf", "psf"),
        ("python-2", "psf"),
        ("mpl", "mpl"),
        ("unlicense", "public-domain"),
        ("cc0", "public-domain"),
        ("lgpl", "lgpl"),
        ("agpl", "agpl"),
        ("gpl", "gpl"),
    ):
        if text.startswith(prefix):
            return name
    return f"other:{licence}"


def ids(expression: str) -> list[str]:
    """The licence ids of an SPDX expression (``A OR B``, ``A AND B``, ``A WITH exception``)."""
    parts = re.split(r"\s+(?:AND|OR|WITH)\s+|[()]", expression)
    return [part.strip() for part in parts if part.strip()]


def families(expression: str) -> set[str]:
    return {family(licence) for licence in ids(expression)}


def acceptable(expression: str) -> bool:
    """On the allowlist: one side of an OR is enough, every side of an AND is needed."""
    for alternative in re.split(r"\s+OR\s+", expression):
        licences = ids(alternative)
        if licences and all(family(licence) in ALLOWED_FAMILIES for licence in licences):
            return True
    return False


def declared(name: str) -> str | None:
    """What an installed package says about its own licence, as one expression.

    ``None`` when it is not installed here or says nothing a program can read (a long licence text
    and no usable classifier).
    """
    try:
        meta = metadata.metadata(name)
    except PackageNotFoundError:
        return None
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        return expression
    text = (meta.get("License") or "").strip()
    if text.lower() in ALIASES:
        return ALIASES[text.lower()]
    classifiers = [
        value.split("::")[-1].strip().lower()
        for value in meta.get_all("Classifier") or []
        if value.startswith("License ::")
    ]
    known = [ALIASES[value] for value in classifiers if value in ALIASES]
    return " OR ".join(known) if known else None


def locked() -> list[str]:
    """The packages of the lock, without the project itself."""
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = canonical(pyproject["project"]["name"])
    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return sorted(
        canonical(package["name"])
        for package in lock["package"]
        if canonical(package["name"]) != project
    )


def test_every_package_in_the_lock_has_a_licence_entry_and_none_is_left_over() -> None:
    in_lock, in_table = set(locked()), {canonical(name) for name in LICENCES}
    assert not in_lock - in_table, (
        f"in uv.lock but not in LICENCES: {sorted(in_lock - in_table)}. Read the licence of each "
        "(its project page or its LICENSE file), add it to LICENCES, and if it is not on the "
        "allowlist it needs a review first (CONTRIBUTING.md)."
    )
    assert not in_table - in_lock, f"in LICENCES but no longer locked: {sorted(in_table - in_lock)}"


def test_every_licence_is_on_the_allowlist_or_a_reviewed_exception() -> None:
    refused = {
        name: licence
        for name, licence in LICENCES.items()
        if not acceptable(licence) and name not in REVIEWED
    }
    assert not refused, (
        f"licences that are neither on the allowlist nor reviewed: {refused}. GPL and AGPL "
        "cannot be shipped with an Apache-2.0 project; for anything else ask first."
    )


def test_the_reviewed_exceptions_still_apply() -> None:
    for name, (licence, reason) in REVIEWED.items():
        assert LICENCES.get(name) == licence, f"{name}: the table says {LICENCES.get(name)}"
        assert not acceptable(licence), f"{name} is on the allowlist now: drop the exception"
        assert reason.strip(), f"{name}: an exception needs its reason"
        assert "lgpl" in families(licence), f"{name}: only the LGPL is reviewed here, not {licence}"


def test_no_gpl_or_agpl_is_in_the_table() -> None:
    copyleft = {name: lic for name, lic in LICENCES.items() if {"gpl", "agpl"} & families(lic)}
    assert not copyleft, f"strong copyleft in the dependencies: {copyleft}"


def disagreements() -> tuple[dict[str, dict[str, str]], int]:
    """Installed packages whose own metadata names other licences than the table, and how many
    could be compared at all."""
    disagree: dict[str, dict[str, str]] = {}
    compared = 0
    for name, licence in LICENCES.items():
        found = declared(name)
        if found is None:
            continue  # not installed here, or it says nothing a program can read
        compared += 1
        if families(found) != families(licence):
            disagree[name] = {"table": licence, "package says": found}
    return disagree, compared


def test_what_an_installed_package_says_agrees_with_the_table() -> None:
    """A new release can change a licence; the lock pins versions, but the table was read once."""
    disagree, compared = disagreements()
    assert not disagree, f"the package metadata and LICENCES differ: {disagree}"
    assert compared >= 60, f"only {compared} packages could be read: is the environment synced?"


def test_the_allowlist_understands_spdx_expressions() -> None:
    assert acceptable("MIT") and acceptable("Apache-2.0 OR BSD-3-Clause")
    assert acceptable("MIT AND PSF-2.0") and acceptable("Unlicense") and acceptable("0BSD")
    assert acceptable("GPL-3.0-only OR MIT")  # one side of an OR is enough
    assert not acceptable("MIT AND GPL-3.0-only")  # every side of an AND is needed
    assert not acceptable("LGPL-3.0-only") and not acceptable("AGPL-3.0-or-later")
    assert not acceptable("GPL-2.0-only WITH Classpath-exception-2.0")
    assert not acceptable("Proprietary") and not acceptable("")


def test_a_changed_licence_upstream_is_noticed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(LICENCES, "flask", "GPL-3.0-only")  # as if the table had been wrong
    disagree, _ = disagreements()
    assert "flask" in disagree
    assert not acceptable(LICENCES["flask"])
    assert "flask" in {name for name, lic in LICENCES.items() if {"gpl"} & families(lic)}


def test_the_project_itself_is_apache_2_0() -> None:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license"] == "Apache-2.0"
    text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in text and "Version 2.0" in text
