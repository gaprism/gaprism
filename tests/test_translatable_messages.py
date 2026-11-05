"""What a screen translates has to exist in the source as a plain string.

A catalogue lists the sentences that its extraction finds, and extraction reads string literals, not
what a program builds from pieces. The errors and validators whose text a screen shows through
gettext (``UserAdminError``, ``AccountExistsError``, ``ScopeValidationError``, ``Entered``,
``AtMost``, ``Chosen``: scripts/translations.py calls them carriers) are therefore made with a
literal, or with a constant that ``N_`` marks. What varies goes in as a ``%(name)s`` parameter
(``UserAdminError("Too many (%(limit)s).", limit=5)``), never into an f-string.

A constant that is a plain string is refused: it would reach the screen in English in every
language, because no extraction sees it. Write ``TOO_MANY = N_("Too many (%(limit)s).")``."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.helpers import load_script

APP = Path(__file__).resolve().parents[1] / "app"
CARRIERS: dict[str, int] = load_script("translations").CARRIERS


def _name(function: ast.expr) -> str:
    if isinstance(function, ast.Name):
        return function.id
    return function.attr if isinstance(function, ast.Attribute) else ""


def marked_constants(tree: ast.Module) -> set[str]:
    """The names the module sets at its top level to a sentence that ``N_`` marks."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Call)
            and _name(value.func) == "N_"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Constant)
            and isinstance(value.args[0].value, str)
        ):
            names.add(target.id)
    return names


def carried(source: str) -> list[ast.expr]:
    """The sentence of every error and validator in ``source`` that a screen translates."""
    sentences = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            index = CARRIERS.get(_name(node.func))
            if index is not None and len(node.args) >= index:
                sentences.append(node.args[index - 1])
    return sentences


def unlistable(source: str, marked_elsewhere: frozenset[str] = frozenset()) -> list[str]:
    """The sentences in ``source`` that no extraction can list: line and what builds each.
    ``marked_elsewhere`` are the constants that other modules mark (an import brings the name)."""
    marked = marked_constants(ast.parse(source)) | marked_elsewhere
    found = []
    for text in carried(source):
        plain = isinstance(text, ast.Constant) and isinstance(text.value, str)
        named = isinstance(text, ast.Name) and text.id in marked
        if not (plain or named):
            found.append(f"line {text.lineno}: {ast.unparse(text)}")
    return found


@pytest.mark.parametrize(
    "source",
    [
        'raise UserAdminError(f"This is the last: {what} would leave nobody")',
        'raise UserAdminError("This is the last: " + what)',
        'raise UserAdminError("This is the last: %s" % what)',
        'raise UserAdminError("This is the last: {}".format(what))',
        "raise UserAdminError(text)",  # a name that no module marks
        'raise scope.ScopeValidationError(f"Enter {what}")',
        'raise AccountExistsError(f"{email} exists")',
        'SENTENCE = "A constant."\nraise UserAdminError(SENTENCE)',  # plain: no extraction sees it
        "SENTENCE = N_(text)\nraise UserAdminError(SENTENCE)",  # marks a name, not a sentence
        'validators = [Entered(f"Enter {what}")]',
        'validators = [AtMost(5, f"At most {count}")]',
        "validators = [Chosen(refusal)]",
    ],
)
def test_the_check_refuses_a_text_that_no_extraction_can_list(source: str) -> None:
    assert len(unlistable(source)) == 1, source


@pytest.mark.parametrize(
    "source",
    [
        'raise UserAdminError("A whole sentence.")',
        'raise UserAdminError("Too many (%(limit)s). Withdraw some.", limit=5)',
        'raise UserAdminError("One sentence " "in two literals.")',
        'SENTENCE = N_("A constant.")\nraise UserAdminError(SENTENCE)',
        'SENTENCE: str = N_("A constant.")\nraise ScopeValidationError(SENTENCE)',
        'validators = [Entered("Enter a name."), AtMost(5, "At most %(max)d."), Chosen("Choose.")]',
        'raise ValueError(f"{what}")',  # not an error whose text a screen translates
        "raise UserAdminError()",  # no sentence to list
    ],
)
def test_the_check_accepts_a_sentence_that_a_catalogue_can_list(source: str) -> None:
    assert unlistable(source) == [], source


def test_a_constant_that_another_module_marks_is_accepted_where_it_is_imported() -> None:
    source = "validators = [Entered(EMPTY)]"
    assert len(unlistable(source)) == 1
    assert unlistable(source, frozenset({"EMPTY"})) == []


def test_every_sentence_a_screen_translates_is_a_plain_string_or_a_marked_constant() -> None:
    trees = {
        path: ast.parse(path.read_text(encoding="utf-8")) for path in sorted(APP.rglob("*.py"))
    }
    elsewhere = frozenset().union(*(marked_constants(tree) for tree in trees.values()))
    offenders = {}
    for path in trees:
        found = unlistable(path.read_text(encoding="utf-8"), elsewhere)
        if found:
            offenders[path.relative_to(APP.parent).as_posix()] = found
    assert not offenders, f"built from pieces, so no catalogue can list them: {offenders}"


def test_the_check_reaches_the_places_that_make_them() -> None:
    files = {path.name for path in APP.rglob("*.py") if carried(path.read_text(encoding="utf-8"))}
    assert {"users.py", "invitations.py", "scope.py", "assessments.py", "forms.py"} <= files
