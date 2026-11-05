"""The message catalogues of the application.

    uv run python scripts/translations.py extract   # app/translations/messages.pot from the source
    uv run python scripts/translations.py update    # extract, then bring every .po in step with it
    uv run python scripts/translations.py compile   # the .mo files that the application loads
    uv run python scripts/translations.py status    # what is translated, what is missing

The template (messages.pot) lists every sentence that the source marks for translation; a catalogue
(de_CH/LC_MESSAGES/messages.po) holds the translation of each. The three kinds of file are all
committed: the image copies app/, so nothing is built when the application is deployed.
docs/translation.md says how a sentence is written and how it is translated.

The files are written so that a diff shows sentences and nothing else: the places of a sentence are
file names without line numbers, and no header holds a date of today.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import re
import sys
from collections.abc import Iterable, Sequence
from io import BytesIO
from pathlib import Path

from babel import Locale
from babel.messages import Catalog, Message
from babel.messages.extract import extract_from_dir
from babel.messages.mofile import read_mo, write_mo
from babel.messages.pofile import read_po, write_po

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
TRANSLATIONS = APP / "translations"
TEMPLATE = TRANSLATIONS / "messages.pot"

SOURCE_LOCALE = "en"  # the language the source is written in: it needs no catalogue
LOCALES = ("de_CH",)  # the languages that are translated; add a code to start another
PROJECT = "Gaprism"
CATALOGUE_VERSION = "1"  # of the catalogues, not of the application: it must not change per release
FIXED_DATE = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)  # a header holds no date of today

# What the extraction reads: code, and the templates (relative to the application folder).
METHODS = [("**.py", "python"), ("templates/**.html", "jinja2")]
OPTIONS = {"templates/**.html": {"extensions": "jinja2.ext.i18n"}}
# The calls whose argument is a sentence that is translated later, when a screen shows it: an error
# or a validator carries it (the argument it is, counted from 1). The sentence has to be written
# there as a plain string, or as a constant that N_ marks: tests/test_translatable_messages.py.
CARRIERS = {
    "UserAdminError": 1,
    "AccountExistsError": 1,
    "ScopeValidationError": 1,
    "Entered": 1,
    "AtMost": 2,
    "Chosen": 1,
}
# The calls whose argument is a sentence, and which argument it is (counted from 1).
KEYWORDS: dict[str, tuple[int, ...] | None] = {
    "_": None,
    "gettext": None,
    "lazy_gettext": None,
    "ngettext": (1, 2),
    "N_": None,  # marks a sentence that is translated later, where it is shown (app/messages.py)
    **{name: (index,) for name, index in CARRIERS.items()},
}
COMMENT_TAG = "TRANSLATORS:"  # a comment that starts with this, above a sentence, goes to the file

POT_HEADER = (
    "# Gaprism, message template.\n"
    "# Written by scripts/translations.py from the sentences that the source marks: do not edit.\n"
)
PO_HEADER = (
    "# Gaprism, translation into {language}.\n"
    "# Edit the msgstr lines; scripts/translations.py keeps the rest in step with the source.\n"
)

# %(name)s, %(num)d and the like: what a sentence is filled with when it is shown.
PLACEHOLDER = re.compile(r"%\(([A-Za-z_]\w*)\)[#0+\- ]*\d*(?:\.\d+)?[A-Za-z]")
SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"  # Swiss spelling has none: it writes ss

MessageId = str | tuple[str, ...]
Key = tuple[str | None, MessageId]


def po_path(locale: str, folder: Path = TRANSLATIONS) -> Path:
    return folder / locale / "LC_MESSAGES" / "messages.po"


def mo_path(locale: str, folder: Path = TRANSLATIONS) -> Path:
    return folder / locale / "LC_MESSAGES" / "messages.mo"


def offered_languages() -> list[str]:
    """The languages that the installation offers besides the one the source is written in."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from app.config import BaseConfig

    return [code for code in BaseConfig.LANGUAGES if code != SOURCE_LOCALE]


# ------------------------------------------------------------------------------ reading the source


def _descend(path: str) -> bool:
    return Path(path).name not in {"__pycache__", "node_modules"}


def new_template() -> Catalog:
    return Catalog(
        project=PROJECT,
        version=CATALOGUE_VERSION,
        header_comment=POT_HEADER,
        creation_date=FIXED_DATE,
        revision_date=FIXED_DATE,
        charset="utf-8",
        fuzzy=False,  # the header of a catalogue is not a guess
    )


def new_catalogue(locale: str) -> Catalog:
    language = Locale.parse(locale).get_display_name("en")
    catalogue = Catalog(
        locale=locale,
        project=PROJECT,
        version=CATALOGUE_VERSION,
        creation_date=FIXED_DATE,
        revision_date=FIXED_DATE,
        last_translator=PROJECT,
        language_team=PROJECT,
        charset="utf-8",
        fuzzy=False,
    )
    catalogue.header_comment = PO_HEADER.format(language=language)
    return catalogue


def extract(source: Path | None = None) -> Catalog:
    """Every sentence that the code and the templates of ``source`` mark for translation."""
    folder = APP if source is None else source
    template = new_template()
    found = extract_from_dir(
        dirname=str(folder),
        method_map=METHODS,
        options_map=OPTIONS,
        keywords=KEYWORDS,
        comment_tags=(COMMENT_TAG,),
        strip_comment_tags=True,
        directory_filter=_descend,
    )
    for filename, lineno, message, comments, context in found:
        place = f"{folder.name}/{Path(filename).as_posix()}"
        template.add(message, locations=[(place, lineno)], auto_comments=comments, context=context)
    return template


# ------------------------------------------------------------------------------ reading and writing


def read_catalogue(path: Path) -> Catalog:
    with path.open("rb") as stream:
        return read_po(stream)


def write_catalogue(path: Path, catalogue: Catalog) -> None:
    """Write a .pot or .po so that two writes of the same sentences are the same bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        write_po(
            stream,
            catalogue,
            width=100,
            sort_by_file=True,
            ignore_obsolete=True,
            include_previous=True,
            include_lineno=False,
        )


def merge(template: Catalog, catalogue: Catalog) -> Catalog:
    """Bring ``catalogue`` in step with ``template``: what is translated stays, a new sentence is
    added empty, a changed one gets the translation of the sentence it replaces as a guess (marked
    fuzzy), and what the source no longer says is dropped (git keeps its history).

    Babel can guess too, but it treats an untranslated plural as translated (its forms are a pair
    of empty strings) and then offers it as the original of any new sentence that looks like it.
    So Babel is told not to, and only a sentence that has a translation can be the original."""
    before = {_key(message) for message in catalogue if message.id}
    catalogue.update(template, no_fuzzy_matching=True, update_header_comment=False)
    pool = {_key(old): old for old in catalogue.obsolete.values() if old.id and _translated(old)}
    for message in catalogue:
        if not message.id or _key(message) in before or _translated(message) or not pool:
            continue
        names = {_first(key[1]).lower().strip(): key for key in pool}
        close = difflib.get_close_matches(_first(message.id).lower().strip(), list(names), n=1)
        if close:
            _guess(message, pool.pop(names[close[0]]), catalogue.num_plurals)
    catalogue.obsolete.clear()
    for message in catalogue:
        if message.id and message.string is None:  # new: a catalogue that is read back says ""
            message.string = ""
    return catalogue


def _guess(message: Message, original: Message, num_plurals: int) -> None:
    """Give ``message`` the translation of ``original``, the sentence it replaces, as a guess."""
    forms = _forms(original.string)
    if isinstance(message.id, str):
        message.string = forms[0]
    else:
        message.string = tuple((forms + [""] * num_plurals)[:num_plurals])
    message.flags.add("fuzzy")
    message.previous_id = [original.id] if isinstance(original.id, str) else list(original.id)


# ------------------------------------------------------------------------------ comparing


def _identity(value: str | Iterable[str]) -> MessageId:
    """A sentence, or the pair of a sentence and its plural, as something that can be a key (the
    reader of a .mo gives a list)."""
    return value if isinstance(value, str) else tuple(value)


def _key(message: Message) -> Key:
    return (message.context, _identity(message.id))


def _forms(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _first(message_id: MessageId) -> str:
    """The sentence itself, or the singular of a sentence with a plural."""
    return message_id if isinstance(message_id, str) else message_id[0]


def _label(message_id: MessageId) -> str:
    text = _first(message_id)
    return repr(text if len(text) <= 60 else text[:57] + "...")


def _tokens(text: str) -> set[str]:
    return {match.group(0) for match in PLACEHOLDER.finditer(text)}


def _shown(tokens: set[str]) -> str:
    return ", ".join(sorted(tokens)) if tokens else "none"


def _stray_percent(text: str) -> bool:
    """A percent sign that is neither %% nor part of a placeholder. A template fills every sentence
    in, so "100 % sicher" would be read as the conversion "% s" and eat a value."""
    return "%" in PLACEHOLDER.sub("", text.replace("%%", ""))


def _translated(message: Message) -> bool:
    forms = _forms(message.string)
    return bool(forms) and all(forms)


def differences(committed: Catalog, current: Catalog) -> list[str]:
    """How the committed template differs from what the source says now (empty: it is current)."""

    def places(catalogue: Catalog) -> dict[Key, frozenset[str]]:
        return {
            _key(message): frozenset(name for name, _line in message.locations)
            for message in catalogue
            if message.id
        }

    before, now = places(committed), places(current)
    changes = [f"{_label(key[1])}: new in the source" for key in now.keys() - before.keys()]
    changes += [f"{_label(key[1])}: no longer in the source" for key in before.keys() - now.keys()]
    for key in before.keys() & now.keys():
        if before[key] != now[key]:
            changes.append(f"{_label(key[1])}: now found in {', '.join(sorted(now[key]))}")
    return sorted(changes)


def _form_name(index: int, plural: bool) -> str:
    return ("first", "second", "third")[min(index, 2)] + " form" if plural else "translation"


def _message_problems(
    source: Message, message: Message, num_plurals: int, *, complete: bool
) -> list[str]:
    label = _label(_identity(message.id))
    wanted = _forms(source.id)
    strings = _forms(message.string)
    plural = len(wanted) > 1
    problems: list[str] = []
    if plural and len(strings) != num_plurals:
        problems.append(f"{label}: {len(strings)} forms where the language has {num_plurals}")
    if complete and not _translated(message):
        problems.append(f"{label}: no translation")
    if complete and message.fuzzy:
        problems.append(f"{label}: fuzzy (check the translation, then remove the flag)")
    for index, text in enumerate(strings):
        if not text:
            continue
        form = _form_name(index, plural)
        expected, got = _tokens(wanted[min(index, len(wanted) - 1)]), _tokens(text)
        if got != expected:
            problems.append(
                f"{label}: placeholders differ in the {form} "
                f"(sentence: {_shown(expected)}; translation: {_shown(got)})"
            )
        if _stray_percent(text):
            problems.append(
                f"{label}: the {form} has a percent sign that is not part of a placeholder; "
                "write %% for a literal one"
            )
        if SHARP_S in text:
            problems.append(f"{label}: the {form} has a sharp s; Swiss spelling writes ss")
    return problems


def catalogue_problems(template: Catalog, catalogue: Catalog, *, complete: bool) -> list[str]:
    """What is wrong with ``catalogue``: out of step with the template, a translation that breaks
    a placeholder, a percent sign or the spelling. With ``complete`` (a language that the
    installation offers) a missing or fuzzy translation is wrong too."""
    wanted = {_key(message): message for message in template if message.id}
    have = {_key(message): message for message in catalogue if message.id}
    problems = [
        f"{_label(key[1])}: not in the catalogue (run update)"
        for key in wanted.keys() - have.keys()
    ]
    problems += [
        f"{_label(key[1])}: no longer in the source (run update)"
        for key in have.keys() - wanted.keys()
    ]
    for key, message in have.items():
        if key in wanted:
            problems += _message_problems(
                wanted[key], message, catalogue.num_plurals, complete=complete
            )
    return sorted(problems)


# ------------------------------------------------------------------------------ compiling


def compile_mo(catalogue: Catalog) -> bytes:
    """The .mo of ``catalogue``: what is translated, and not what is empty or a guess (fuzzy)."""
    buffer = BytesIO()
    write_mo(buffer, catalogue)
    return buffer.getvalue()


def _compiled(data: bytes) -> dict[Key, MessageId]:
    return {
        _key(message): _identity(message.string) for message in read_mo(BytesIO(data)) if message.id
    }


def mo_problems(catalogue: Catalog, compiled: bytes | None) -> list[str]:
    """Is the compiled file what ``catalogue`` compiles to? Compared by the sentences in it and
    not by the bytes: the header carries the version of Babel that wrote it."""
    if compiled is None:
        return ["there is no compiled catalogue (run compile)"]
    if _compiled(compiled) != _compiled(compile_mo(catalogue)):
        return ["the compiled catalogue is out of date (run compile)"]
    return []


# ------------------------------------------------------------------------------ the commands


def _counts(catalogue: Catalog) -> tuple[int, int, int, int]:
    """Sentences, translated ones, missing ones, fuzzy ones."""
    messages = [message for message in catalogue if message.id]
    translated = [message for message in messages if _translated(message)]
    return (
        len(messages),
        sum(1 for message in translated if not message.fuzzy),
        len(messages) - len(translated),
        sum(1 for message in messages if message.fuzzy),
    )


def _show(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _extract_command(root: Path) -> Catalog:
    target = root / "app" / "translations" / "messages.pot"
    template = extract(root / "app")
    write_catalogue(target, template)
    print(f"{sum(1 for message in template if message.id)} sentences in {_show(target, root)}")
    return template


def _update_command(root: Path) -> int:
    folder = root / "app" / "translations"
    template = _extract_command(root)
    for locale in LOCALES:
        path = po_path(locale, folder)
        catalogue = read_catalogue(path) if path.exists() else new_catalogue(locale)
        known = {_key(message) for message in catalogue if message.id}
        merge(template, catalogue)
        write_catalogue(path, catalogue)
        added = len({_key(message) for message in catalogue if message.id} - known)
        total, done, missing, fuzzy = _counts(catalogue)
        print(
            f"{locale}: {added} added; {done} of {total} translated, "
            f"{missing} missing, {fuzzy} fuzzy ({_show(path, root)})"
        )
    return 0


def _compile_command(root: Path, offered: Sequence[str]) -> int:
    folder = root / "app" / "translations"
    if not (folder / "messages.pot").exists():
        print("There is no template yet: run update")
        return 1
    template = read_catalogue(folder / "messages.pot")
    status = 0
    for locale in LOCALES:
        path = po_path(locale, folder)
        if not path.exists():
            continue
        catalogue = read_catalogue(path)
        problems = catalogue_problems(template, catalogue, complete=locale in offered)
        if problems:
            status = 1
            print(f"{locale}: not compiled, {len(problems)} problems:")
            for problem in problems[:25]:
                print(f"  {problem}")
            continue
        target = mo_path(locale, folder)
        target.write_bytes(compile_mo(catalogue))
        print(f"{locale}: {_counts(catalogue)[1]} translations in {_show(target, root)}")
    return status


def _status_command(root: Path, offered: Sequence[str]) -> int:
    folder = root / "app" / "translations"
    if not (folder / "messages.pot").exists():
        print("There is no template yet: run update")
        return 1
    template = read_catalogue(folder / "messages.pot")
    status = 0
    stale = differences(template, extract(root / "app"))
    if stale:
        status = 1
        print(f"The template is out of date with the source ({len(stale)} differences): run update")
        for line in stale[:10]:
            print(f"  {line}")
    for locale in LOCALES:
        path = po_path(locale, folder)
        if not path.exists():
            print(f"{locale}: no catalogue yet (run update)")
            continue
        catalogue = read_catalogue(path)
        total, done, missing, fuzzy = _counts(catalogue)
        mark = " (offered)" if locale in offered else ""
        print(f"{locale}: {done} of {total} translated, {missing} missing, {fuzzy} fuzzy{mark}")
        problems = catalogue_problems(template, catalogue, complete=locale in offered)
        if problems:
            status = 1
            for problem in problems[:10]:
                print(f"  {problem}")
            if len(problems) > 10:
                print(f"  ... and {len(problems) - 10} more")
    return status


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = ROOT,
    offered: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("extract", "update", "compile", "status"))
    command = parser.parse_args(argv).command
    languages = offered_languages() if offered is None else list(offered)
    if command == "extract":
        _extract_command(root)
        return 0
    if command == "update":
        return _update_command(root)
    if command == "compile":
        return _compile_command(root, languages)
    return _status_command(root, languages)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # the sentences have umlauts; some consoles do not
    raise SystemExit(main())
