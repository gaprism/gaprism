"""What a screen translates has to exist in the source as a plain string.

A catalogue lists the sentences that its extraction finds, and extraction reads string literals, not
what a program builds from pieces. The errors whose text a screen shows through gettext
(``UserAdminError``, ``AccountExistsError``, ``ScopeValidationError``) are therefore raised with a
literal, or with a constant of the module that is one. What varies goes in as a ``%(name)s``
parameter (``UserAdminError("Too many (%(limit)s).", limit=5)``), never into an f-string."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app"
TRANSLATED_ERRORS = {"UserAdminError", "AccountExistsError", "ScopeValidationError"}


def _name(function: ast.expr) -> str:
    if isinstance(function, ast.Name):
        return function.id
    return function.attr if isinstance(function, ast.Attribute) else ""


def _constants(tree: ast.Module) -> set[str]:
    """The names the module sets to a plain string at its top level."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if isinstance(target, ast.Name) and isinstance(value, ast.Constant):
            if isinstance(value.value, str):
                names.add(target.id)
    return names


def raised_errors(source: str) -> list[ast.Call]:
    """Every place in ``source`` that makes one of the errors a screen translates."""
    return [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and node.args and _name(node.func) in TRANSLATED_ERRORS
    ]


def unlistable(source: str) -> list[str]:
    """The errors in ``source`` whose text is built from pieces: line and what builds it."""
    constants = _constants(ast.parse(source))
    found = []
    for call in raised_errors(source):
        text = call.args[0]
        plain = isinstance(text, ast.Constant) and isinstance(text.value, str)
        named = isinstance(text, ast.Name) and text.id in constants
        if not (plain or named):
            found.append(f"line {call.lineno}: {ast.unparse(text)}")
    return found


@pytest.mark.parametrize(
    "source",
    [
        'raise UserAdminError(f"This is the last: {what} would leave nobody")',
        'raise UserAdminError("This is the last: " + what)',
        'raise UserAdminError("This is the last: %s" % what)',
        'raise UserAdminError("This is the last: {}".format(what))',
        "raise UserAdminError(text)",  # a name that the module does not set to a string
        'raise scope.ScopeValidationError(f"Enter {what}")',
        'raise AccountExistsError(f"{email} exists")',
    ],
)
def test_the_check_refuses_a_text_that_is_built_from_pieces(source: str) -> None:
    assert len(unlistable(source)) == 1, source


@pytest.mark.parametrize(
    "source",
    [
        'raise UserAdminError("A whole sentence.")',
        'raise UserAdminError("Too many (%(limit)s). Withdraw some.", limit=5)',
        'raise UserAdminError("One sentence " "in two literals.")',
        'SENTENCE = "A constant."\nraise UserAdminError(SENTENCE)',
        'SENTENCE: str = "A constant."\nraise ScopeValidationError(SENTENCE)',
        'raise ValueError(f"{what}")',  # not an error whose text a screen translates
    ],
)
def test_the_check_accepts_a_sentence_that_a_catalogue_can_list(source: str) -> None:
    assert unlistable(source) == [], source


def test_every_error_a_screen_translates_is_raised_with_a_plain_string() -> None:
    offenders = {}
    for path in sorted(APP.rglob("*.py")):
        found = unlistable(path.read_text(encoding="utf-8"))
        if found:
            offenders[path.relative_to(APP.parent).as_posix()] = found
    assert not offenders, f"built from pieces, so no catalogue can list them: {offenders}"


def test_the_check_reaches_the_places_that_raise_them() -> None:
    files = {
        path.name for path in APP.rglob("*.py") if raised_errors(path.read_text(encoding="utf-8"))
    }
    assert {"users.py", "invitations.py", "scope.py", "assessments.py"} <= files
