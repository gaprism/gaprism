"""The message catalogues: the sentences the source says, the German file that follows them, and the
gates that keep the two in step.

scripts/translations.py does the work (extract, update, compile, status); docs/translation.md says
how a sentence is written and translated. These tests run it on small trees of their own, and then
on the real one: the committed template is what the source says, every catalogue follows it and
translates with care, and a language that the installation offers is complete and compiled.
"""

from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path

import pytest
from babel.messages import Catalog
from babel.support import Translations

from tests.helpers import load_script

SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"
OPEN, CLOSE = (
    "\N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}",
    ("\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}"),
)


tr = load_script("translations")

SOURCE = """\
from app.messages import N_

LABELS = {"a": N_("A marked label.")}


def view(n, variable):
    flash(_("A plain sentence."))
    ngettext("%(num)s host", "%(num)s hosts", n)
    gettext("Through gettext.")
    _(variable)
    raise UserAdminError("Too many (%(limit)s).", limit=5)
    raise UserAdminError(NOT_A_LITERAL)
    raise AccountExistsError("Already exists.")
    raise ScopeValidationError("Not a domain.")
    return [Entered("Enter a name."), AtMost(5, "At most %(max)d."), Chosen("Choose a file.")]
"""
PAGE = "<p>{{ _('From a template.') }}</p>{{ ngettext('%(num)s item', '%(num)s items', n) }}"
EVERYTHING = {
    "A marked label.",
    "A plain sentence.",
    ("%(num)s host", "%(num)s hosts"),
    "Through gettext.",
    "Too many (%(limit)s).",
    "Already exists.",
    "Not a domain.",
    "Enter a name.",
    "At most %(max)d.",
    "Choose a file.",
    "From a template.",
    ("%(num)s item", "%(num)s items"),
}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small application folder: code, a template in a subfolder, and files that are not read."""
    app = tmp_path / "app"
    (app / "templates" / "deep").mkdir(parents=True)
    (app / "static").mkdir()
    (app / "views.py").write_text(SOURCE, encoding="utf-8")
    (app / "templates" / "deep" / "page.html").write_text(PAGE, encoding="utf-8")
    (app / "static" / "app.js").write_text("_('Not a sentence of ours.')", encoding="utf-8")
    (app / "notes.txt").write_text("_('Nor this one.')", encoding="utf-8")
    return app


def sentences(catalogue: Catalog) -> set[str | tuple[str, ...]]:
    return {message.id for message in catalogue if message.id}


def template_of(*ids: str | tuple[str, str]) -> Catalog:
    template = Catalog(project="Gaprism")
    for sentence in ids:
        template.add(sentence, locations=[("app/x.py", 1)])
    return template


def german_of(pairs: dict[str, str]) -> Catalog:
    catalogue = tr.new_catalogue("de_CH")
    for english, german in pairs.items():
        catalogue.add(english, german)
    return catalogue


# ------------------------------------------------------------------------------ extraction


def test_the_extraction_finds_what_a_screen_shows(tree: Path) -> None:
    assert sentences(tr.extract(tree)) == EVERYTHING


def test_a_sentence_inside_an_f_string_is_found_whatever_the_version_of_python() -> None:
    """Babel reads tokens, and before Python 3.12 an f-string is one token: the sentence in
    ``{_('...')}`` was found on 3.12 and not on 3.11, so the template depended on the Python that
    wrote it (the first CI run of the German catalogue failed on 3.11 for that). The syntax tree is
    the same on every version, so the sentences are read from it."""
    source = b"""text = f"{_('inside')} and {ngettext('one', 'many', n)}"\n"""
    found = [
        (name, messages)
        for _line, name, messages, _comments in tr.extract_python(
            BytesIO(source), tr.KEYWORDS.keys(), (), {}
        )
    ]
    assert found == [("_", ["inside"]), ("ngettext", ["one", "many", None])]
    assert tr.METHODS[0] == ("**.py", tr.extract_python)


def test_a_sentence_knows_its_files_and_the_written_file_has_no_line_numbers(
    tree: Path, tmp_path: Path
) -> None:
    catalogue = tr.extract(tree)
    assert {name for name, _line in catalogue["From a template."].locations} == {
        "app/templates/deep/page.html"
    }
    written = tmp_path / "messages.pot"
    tr.write_catalogue(written, catalogue)
    text = written.read_text(encoding="utf-8")
    assert "#: app/views.py\n" in text
    assert not re.search(r"^#: \S+:\d+", text, re.M), "a line number changes with every edit"


def test_a_sentence_used_in_two_places_is_one_entry_that_lists_both_files(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "one.py").write_text('flash(_("Shared sentence."))\n', encoding="utf-8")
    (app / "two.py").write_text('flash(_("Shared sentence."))\n', encoding="utf-8")
    catalogue = tr.extract(app)
    assert len(sentences(catalogue)) == 1
    assert {name for name, _line in catalogue["Shared sentence."].locations} == {
        "app/one.py",
        "app/two.py",
    }


def test_the_file_is_the_same_every_time_it_is_written_and_holds_no_date_of_today(
    tree: Path, tmp_path: Path
) -> None:
    first, second = tmp_path / "a.pot", tmp_path / "b.pot"
    tr.write_catalogue(first, tr.extract(tree))
    tr.write_catalogue(second, tr.extract(tree))
    assert first.read_bytes() == second.read_bytes()
    assert tr.FIXED_DATE.strftime("%Y-%m-%d") in first.read_text(encoding="utf-8")


def test_a_german_catalogue_says_what_language_it_is_and_how_the_plural_works(
    tmp_path: Path,
) -> None:
    written = tmp_path / "messages.po"
    tr.write_catalogue(written, tr.new_catalogue("de_CH"))
    header = written.read_text(encoding="utf-8")
    assert "Language: de_CH" in header
    assert "Plural-Forms: nplurals=2; plural=(n != 1);" in header
    assert "charset=utf-8" in header


# ------------------------------------------------------------------------------ update


def test_update_keeps_what_is_translated_adds_what_is_new_and_drops_what_is_gone() -> None:
    german = german_of({"One.": "Eins.", "Two.": "Zwei."})
    merged = tr.merge(template_of("One.", "Three."), german)
    assert {m.id: m.string for m in merged if m.id} == {"One.": "Eins.", "Three.": ""}
    assert not merged.obsolete, "an obsolete entry is dropped: the history of git keeps it"


def test_update_marks_a_changed_sentence_fuzzy_and_keeps_the_old_translation() -> None:
    german = german_of({"Sign in to continue working.": "Melden Sie sich an."})
    merged = tr.merge(template_of("Sign in again to continue working."), german)
    message = merged["Sign in again to continue working."]
    assert message.fuzzy
    assert message.string == "Melden Sie sich an."


def test_a_new_sentence_is_never_matched_to_one_that_has_no_translation_yet() -> None:
    """Babel counts an untranslated plural as translated (its forms are a pair of empty strings),
    and made "The request could not be completed." a fuzzy guess of a sentence about hosts."""
    old = tr.new_catalogue("de_CH")
    old.add(("%(num)s host could not be located", "%(num)s hosts could not be located"))
    merged = tr.merge(template_of("The request could not be completed."), old)
    message = merged["The request could not be completed."]
    assert not message.fuzzy
    assert not message.string


def test_a_changed_plural_sentence_keeps_the_translation_of_both_forms_as_a_guess() -> None:
    old = tr.new_catalogue("de_CH")
    old.add(("%(num)s host", "%(num)s hosts"), ("%(num)s Host", "%(num)s Hosts"))
    merged = tr.merge(template_of(("%(num)s host found", "%(num)s hosts found")), old)
    message = merged[("%(num)s host found", "%(num)s hosts found")]
    assert message.fuzzy
    assert message.string == ("%(num)s Host", "%(num)s Hosts")


def test_a_new_plural_sentence_gets_a_place_for_each_german_form() -> None:
    merged = tr.merge(template_of(("%(num)s host", "%(num)s hosts")), tr.new_catalogue("de_CH"))
    assert [m.string for m in merged if m.id] == [("", "")]


# ------------------------------------------------------------------------------ problems


def found(
    msgid: str | tuple[str, str], msgstr: str | tuple[str, str], *, complete: bool = False
) -> list[str]:
    catalogue = tr.new_catalogue("de_CH")
    catalogue.add(msgid, msgstr)
    return tr.catalogue_problems(template_of(msgid), catalogue, complete=complete)


@pytest.mark.parametrize(
    ("msgid", "msgstr"),
    [
        ("Hello %(name)s, %(num)d hosts.", "Guten Tag %(name)s, %(num)d Hosts."),
        ("Hello %(name)s.", "%(name)s, guten Tag."),  # the order of the words is the translator's
        (("%(num)s host", "%(num)s hosts"), ("%(num)s Host", "%(num)s Hosts")),
        ('Say "yes".', f"Sagen Sie {OPEN}ja{CLOSE}."),
        ("Fully loaded: 100%%.", "Voll ausgelastet: 100%%."),  # a literal percent sign is %%
    ],
)
def test_a_careful_translation_has_no_problem(
    msgid: str | tuple[str, str], msgstr: str | tuple[str, str]
) -> None:
    assert found(msgid, msgstr, complete=True) == []


@pytest.mark.parametrize(
    ("msgid", "msgstr", "expected"),
    [
        ("Hello %(name)s.", "Guten Tag.", "%(name)s"),  # a placeholder was dropped
        ("Hello.", "Guten Tag %(name)s.", "%(name)s"),  # a placeholder was made up
        ("Hello %(name)s.", "Guten Tag %(user)s.", "%(user)s"),  # ... or renamed
        ("Hello %(num)d.", "Guten Tag %(num)s.", "%(num)"),  # ... or given another kind
        ("Reload.", "Neu laden, 100 % sicher.", "percent sign"),  # "% s" would eat a value
        ("Street.", f"Fu{SHARP_S} und Weg.", "sharp s"),  # Swiss spelling
        (("%(num)s host", "%(num)s hosts"), ("%(num)s Host", "Hosts"), "second form"),
    ],
)
def test_a_careless_translation_is_named(
    msgid: str | tuple[str, str], msgstr: str | tuple[str, str], expected: str
) -> None:
    problems = found(msgid, msgstr)
    assert len(problems) == 1, problems
    assert expected in problems[0]


def test_a_missing_translation_is_a_problem_only_where_the_catalogue_must_be_complete() -> None:
    template = template_of("One.", "Two.")
    german = tr.merge(template, german_of({"One.": "Eins."}))  # "Two." is there, still empty
    assert tr.catalogue_problems(template, german, complete=False) == []
    assert tr.catalogue_problems(template, german, complete=True) == ["'Two.': no translation"]


def test_a_missing_form_of_a_plural_counts_as_missing() -> None:
    problems = found(("%(num)s host", "%(num)s hosts"), ("%(num)s Host", ""), complete=True)
    assert problems == ["'%(num)s host': no translation"]


def test_a_fuzzy_translation_is_a_problem_only_where_the_catalogue_must_be_complete() -> None:
    template = template_of("One.")
    german = german_of({"One.": "Eins."})
    german["One."].flags.add("fuzzy")
    assert tr.catalogue_problems(template, german, complete=False) == []
    problems = tr.catalogue_problems(template, german, complete=True)
    assert len(problems) == 1 and "'One.'" in problems[0] and "fuzzy" in problems[0]


def test_a_catalogue_that_is_out_of_step_with_the_template_names_both_directions() -> None:
    problems = tr.catalogue_problems(
        template_of("New."), german_of({"Old.": "Alt."}), complete=False
    )
    assert sorted(problems) == [
        "'New.': not in the catalogue (run update)",
        "'Old.': no longer in the source (run update)",
    ]


# ------------------------------------------------------------------------------ compile


def test_the_compiled_catalogue_holds_what_is_translated_and_nothing_else() -> None:
    german = german_of({"One.": "Eins."})
    german.add("Two.", "")
    german.add("Fuzzy.", "Unsicher.", flags=["fuzzy"])
    german.add(("%(num)s host", "%(num)s hosts"), ("%(num)s Host", "%(num)s Hosts"))
    translations = Translations(BytesIO(tr.compile_mo(german)))
    assert translations.gettext("One.") == "Eins."
    assert translations.gettext("Two.") == "Two."  # untranslated: the English stays
    assert translations.gettext("Fuzzy.") == "Fuzzy."  # a guess is not shown
    assert translations.ngettext("%(num)s host", "%(num)s hosts", 1) == "%(num)s Host"
    assert translations.ngettext("%(num)s host", "%(num)s hosts", 2) == "%(num)s Hosts"


def test_a_stale_compiled_catalogue_is_found_by_its_messages_not_by_its_bytes() -> None:
    german = german_of({"One.": "Eins."})
    compiled = tr.compile_mo(german)
    assert tr.mo_problems(german, compiled) == []

    german.last_translator = "Somebody else"  # other bytes in the header, the same sentences
    assert tr.compile_mo(german) != compiled
    assert tr.mo_problems(german, compiled) == []

    german.add("Two.", "Zwei.")
    assert tr.mo_problems(german, compiled) == [
        "the compiled catalogue is out of date (run compile)"
    ]
    assert tr.mo_problems(german, None) == ["there is no compiled catalogue (run compile)"]


# ------------------------------------------------------------------------------ the command


def test_the_commands_extract_update_check_and_compile_a_tree_of_their_own(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tree.parent
    folder = tree / "translations"
    german = folder / "de_CH" / "LC_MESSAGES" / "messages.po"

    assert tr.main(["extract"], root=root, offered=[]) == 0
    assert (folder / "messages.pot").is_file() and not german.exists()

    assert tr.main(["update"], root=root, offered=[]) == 0
    assert german.is_file()

    capsys.readouterr()
    assert tr.main(["status"], root=root, offered=[]) == 0  # in progress: nothing is demanded
    assert f"de_CH: 0 of {len(EVERYTHING)} translated" in capsys.readouterr().out
    assert tr.main(["status"], root=root, offered=["de_CH"]) == 1  # offered: it has to be complete

    catalogue = tr.read_catalogue(german)
    catalogue["A plain sentence."].string = "Ein einfacher Satz."
    tr.write_catalogue(german, catalogue)
    assert tr.main(["compile"], root=root, offered=[]) == 0
    compiled = german.with_suffix(".mo").read_bytes()
    assert Translations(BytesIO(compiled)).gettext("A plain sentence.") == "Ein einfacher Satz."


def test_status_names_a_template_that_the_source_has_left_behind(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tree.parent
    assert tr.main(["update"], root=root, offered=[]) == 0
    (tree / "more.py").write_text('flash(_("A sentence written later."))\n', encoding="utf-8")

    capsys.readouterr()
    assert tr.main(["status"], root=root, offered=[]) == 1
    output = capsys.readouterr().out
    assert "A sentence written later." in output and "update" in output


def test_compile_refuses_a_translation_that_breaks_a_placeholder_and_writes_nothing(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tree.parent
    assert tr.main(["update"], root=root, offered=[]) == 0
    german = tree / "translations" / "de_CH" / "LC_MESSAGES" / "messages.po"
    catalogue = tr.read_catalogue(german)
    catalogue["Too many (%(limit)s)."].string = "Zu viele."
    tr.write_catalogue(german, catalogue)

    capsys.readouterr()
    assert tr.main(["compile"], root=root, offered=[]) == 1
    assert "%(limit)s" in capsys.readouterr().out
    assert not german.with_suffix(".mo").exists()


# ------------------------------------------------------------------------------ the real tree


def test_the_committed_template_is_what_the_source_says() -> None:
    changes = tr.differences(tr.read_catalogue(tr.TEMPLATE), tr.extract())
    assert not changes, (
        "The sentences of the source and app/translations/messages.pot differ:\n  "
        + "\n  ".join(changes[:40])
        + "\nRun: uv run python scripts/translations.py update"
    )


@pytest.mark.parametrize("locale", tr.LOCALES)
def test_each_catalogue_follows_the_template_and_translates_with_care(locale: str) -> None:
    path = tr.po_path(locale)
    if not path.exists():
        pytest.skip(f"{locale} has no catalogue yet")
    here = tr.catalogue_problems(
        tr.read_catalogue(tr.TEMPLATE),
        tr.read_catalogue(path),
        complete=locale in tr.offered_languages(),
    )
    assert not here, f"{path.name} of {locale}:\n  " + "\n  ".join(here[:40])


def test_a_language_the_installation_offers_is_complete_and_compiled() -> None:
    for locale in tr.offered_languages():
        path = tr.po_path(locale)
        assert path.is_file(), f"{locale} is offered but has no catalogue at {path}"
        catalogue = tr.read_catalogue(path)
        assert tr.catalogue_problems(tr.read_catalogue(tr.TEMPLATE), catalogue, complete=True) == []
        mo = tr.mo_path(locale)
        assert tr.mo_problems(catalogue, mo.read_bytes() if mo.is_file() else None) == []
