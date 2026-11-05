# Translation

The interface is written in English and available in German as it is written in Switzerland
(`de_CH`). This document says how a sentence is written so that it can be translated, how the
catalogues are kept, and what the tests refuse. [translation-glossary.md](translation-glossary.md)
holds the voice and the terms of the German text.

## Where things are

| What | Where |
|---|---|
| The sentences of the source | `app/translations/messages.pot` (written by the script, never by hand) |
| The German translation | `app/translations/de_CH/LC_MESSAGES/messages.po` (the `msgstr` lines are the translation) |
| What the application loads | `app/translations/de_CH/LC_MESSAGES/messages.mo` |
| The script | `scripts/translations.py` |
| Which languages are offered | `LANGUAGES` in `app/config.py` (the first is the default) |

All three kinds of file are committed. The image copies `app/`, so nothing is built when the
application is deployed. A diff of a catalogue shows sentences and nothing else: places are file
names without line numbers, and no header holds a date.

## Commands

```powershell
uv run python scripts/translations.py update    # read the source, write the .pot, bring the .po in step
uv run python scripts/translations.py status    # what is translated, what is missing, what is stale
uv run python scripts/translations.py compile   # the .mo files (refuses a translation that breaks a placeholder)
```

After you add or change a sentence run `update`, translate the new `msgstr` (a changed sentence
keeps its old translation as a guess marked `fuzzy`: check it and remove the flag), and run
`compile`. A `.po` is an ordinary gettext file: any editor works, and so does Poedit.

## Writing a sentence

- **A whole sentence, in English, through `_()`**: `{{ _('Scan queued.') }}` in a template,
  `_("Scan queued.")` in code. Never glue a sentence from pieces: German orders the words
  differently. What varies goes in as a named parameter:
  `_("Deleted %(domain)s.", domain=domain)`.
- **A plural through `ngettext`**, with `%(num)s`:
  `ngettext('%(num)s host', '%(num)s hosts', n)`. German has two forms, like English.
- **A sentence that is kept somewhere and shown later** (a constant, a table, a message that an
  error or a validator carries, a setting) is marked where it is written with `N_`
  (`from app.messages import N_`) and looked up with `_()` where it is shown. `N_` returns its
  argument and does nothing else; it tells the extraction that the sentence is ours.
- **An error that a screen shows** (`UserAdminError`, `AccountExistsError`,
  `ScopeValidationError`) and a validator that refuses (`Entered`, `AtMost`, `Chosen`) take a plain
  string or a constant marked with `N_`; the screen translates it with
  `_(exc.message, **exc.params)`. `tests/test_translatable_messages.py` refuses an f-string, a
  concatenation, a `%` or `.format` and a constant that `N_` does not mark, because the extraction
  cannot see them and the sentence would stay English.
- **A percent sign** in a sentence is written `%%`. A template fills every sentence in, so
  a lone `%` would be read as a conversion.
- **The words of a library.** Flask-Security words its messages through its own translation
  domain; `app.i18n.SecurityDomain` puts our catalogue behind it. The messages that the screens can
  show are worded in `app/config.py` as `SECURITY_MSG_*`, each text wrapped in `N_`. A message of
  the library that is not listed there stays as the library words it.
- **What is not translated on purpose**: the command line, the log, the generated
  `docs/rules.md`, the facts in the audit log (identifiers, counts, rule ids), and the names of
  Flask-Security's second-factor methods (`authenticator`, `email`, `none`), which its templates
  compare as text: no catalogue entry may change them.

## What the tests keep

`tests/test_translations.py` runs the script on small trees and then on the real one:

1. The committed template is what the source says (otherwise: run `update`).
2. Every catalogue lists exactly the sentences of the template, and every translation that exists
   has the same `%(name)s` placeholders as its sentence (in each plural form), no stray `%`, and
   no `ß` (Swiss spelling writes `ss`).
3. **A language that `LANGUAGES` offers is complete**: no empty or fuzzy translation, and its
   `.mo` holds exactly the sentences of its `.po`. A language that is not offered yet may be
   unfinished, but what is translated has to be right.

So a new `_()` sentence fails the suite until its German translation exists. That is the point:
the German interface is not allowed to fall behind the English one.
