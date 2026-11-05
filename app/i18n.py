"""Minimal gettext integration for Jinja templates and Python code (Babel catalogs, no extras).

Catalogs live in ``app/translations/<locale>/LC_MESSAGES/messages.mo``. Until a catalog exists
for the selected locale every message is returned unchanged, so English works out of the box.

The language of a request is the one the signed-in person chose (``user.locale``), else the one
chosen in this browser (``session["locale"]``, set together with the first), else the best match of
the browser's Accept-Language, else the first of ``LANGUAGES``. Only languages in ``LANGUAGES``
count; the account menu offers the choice when there is more than one.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from gettext import NullTranslations
from pathlib import Path

from babel import Locale, UnknownLocaleError
from babel.support import Translations
from flask import Flask, g, has_request_context, request, session
from flask_login import current_user

TRANSLATIONS_DIR = Path(__file__).parent / "translations"


@dataclass(frozen=True)
class Language:
    """A language the installation offers, as the account menu shows it."""

    code: str  # as in LANGUAGES: "de_CH"
    name: str  # in its own words: "Deutsch"
    current: bool  # the one the page is in


def _account_locale() -> str | None:
    """The language the signed-in person chose, if there is one."""
    try:
        chosen = getattr(current_user, "locale", None) if current_user.is_authenticated else None
    except Exception:  # the database is down: the error page still has to be written
        return None
    return chosen if isinstance(chosen, str) else None


def _from_the_browser(supported: Sequence[str]) -> str | None:
    """The first of the languages the browser asks for (best liked first) that is offered. For each
    one the exact code is tried, then the same language: "de" and "de-DE" are met by "de_CH" when
    that is the German there is. A less liked language never wins over a more liked one."""
    codes = {code: code.replace("_", "-").lower() for code in supported}
    for asked, _quality in request.accept_languages:
        wanted = asked.replace("_", "-").lower()
        for code, normal in codes.items():
            if normal == wanted:
                return code
        for code, normal in codes.items():
            if normal.split("-")[0] == wanted.split("-")[0]:
                return code
    return None


def select_locale(supported: Sequence[str]) -> str:
    """The language of this request, see the top of this module."""
    if has_request_context():
        for chosen in (_account_locale(), session.get("locale")):
            if isinstance(chosen, str) and chosen in supported:
                return chosen
        asked = _from_the_browser(supported)
        if asked:
            return asked
    return supported[0]


def language_names(codes: Sequence[str]) -> dict[str, str]:
    """Each language by its own name ("English", "Deutsch"). The region is added only where two of
    the codes are one language: "Deutsch (Schweiz)" and "Deutsch (Deutschland)", but "Deutsch" when
    there is one German. A code that Babel does not know is its own name."""
    known: dict[str, Locale] = {}
    for code in codes:
        try:
            known[code] = Locale.parse(code)
        except (ValueError, UnknownLocaleError):
            continue
    shared = Counter(locale.language for locale in known.values())
    names: dict[str, str] = {}
    for code in codes:
        locale = known.get(code)
        if locale is None:
            names[code] = code
            continue
        name = (
            locale.get_display_name(locale)
            if shared[locale.language] > 1
            else locale.get_language_name(locale)
        ) or code
        names[code] = name[:1].upper() + name[1:]  # Babel begins the name of French in lower case
    return names


def language_choices(supported: Sequence[str], current: str) -> list[Language]:
    """What the account menu offers: every language by its name, the one in use marked. Nothing
    while there is nothing to choose between."""
    if len(supported) < 2:
        return []
    names = language_names(supported)
    return [Language(code, names[code], code == current) for code in supported]


def _translations() -> NullTranslations:
    if not has_request_context():
        return NullTranslations()
    cached: NullTranslations | None = g.get("_translations")
    if cached is None:
        supported = g.get("_supported_locales") or ["en"]
        locale = select_locale(supported)
        cached = Translations.load(str(TRANSLATIONS_DIR), [locale])
        g._translations = cached
    return cached


def gettext(message: str, **variables: object) -> str:
    """Translate ``message`` for the current request; ``%(name)s`` placeholders are filled."""
    text = _translations().gettext(message)
    return text % variables if variables else text


def ngettext(singular: str, plural: str, n: int, **variables: object) -> str:
    """Translate the right plural form for ``n``; ``%(num)s`` is ``n``, other ``%(name)s`` too."""
    text = _translations().ngettext(singular, plural, n)
    return text % {"num": n, **variables}


class SecurityDomain:
    """Flask-Security's translation domain, with our catalogue behind it. The library words every
    message it shows (``get_message``) through ``i18n_domain.gettext``, and without Flask-Babel its
    own domain returns the text as it is, in every language."""

    def gettext(self, string: str, **variables: object) -> str:
        return gettext(string, **variables)

    def ngettext(self, singular: str, plural: str, num: int, **variables: object) -> str:
        return ngettext(singular, plural, num, **variables)


def init_i18n(app: Flask) -> None:
    """Enable ``{{ _('...') }}`` in templates, and expose the active locale as ``locale`` and the
    languages to choose between as ``languages`` (empty with one language). Flask-Security, when it
    is installed in ``app``, is put on the same catalogue."""
    app.jinja_env.add_extension("jinja2.ext.i18n")
    app.jinja_env.install_gettext_callables(  # type: ignore[attr-defined]
        lambda message: _translations().gettext(message),
        lambda singular, plural, n: _translations().ngettext(singular, plural, n),
        newstyle=True,
    )
    security = app.extensions.get("security")
    if security is not None:
        security.i18n_domain = SecurityDomain()
        app.jinja_env.globals["_fsdomain"] = security.i18n_domain.gettext  # bound at its init

    @app.before_request
    def remember_supported_locales() -> None:
        g._supported_locales = list(app.config["LANGUAGES"])

    @app.context_processor
    def inject_locale() -> dict[str, object]:
        supported = list(app.config["LANGUAGES"])
        chosen = select_locale(supported)
        return {
            "locale": chosen.replace("_", "-"),
            "languages": language_choices(supported, chosen),
        }
