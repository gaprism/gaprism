"""Minimal gettext integration for Jinja templates and Python code (Babel catalogs, no extras).

Catalogs live in ``app/translations/<locale>/LC_MESSAGES/messages.mo``. Until a catalog exists
for the selected locale every message is returned unchanged, so English works out of the box.
"""

from __future__ import annotations

from collections.abc import Sequence
from gettext import NullTranslations
from pathlib import Path

from babel.support import Translations
from flask import Flask, g, has_request_context, request, session

TRANSLATIONS_DIR = Path(__file__).parent / "translations"


def select_locale(supported: Sequence[str]) -> str:
    """Pick the session locale, else the best Accept-Language match, else the first supported."""
    if has_request_context():
        stored = session.get("locale")
        if isinstance(stored, str) and stored in supported:
            return stored
        best = request.accept_languages.best_match(list(supported))
        if best:
            return best
    return supported[0]


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


def init_i18n(app: Flask) -> None:
    """Enable ``{{ _('...') }}`` in templates and expose the active locale as ``locale``."""
    app.jinja_env.add_extension("jinja2.ext.i18n")
    app.jinja_env.install_gettext_callables(  # type: ignore[attr-defined]
        lambda message: _translations().gettext(message),
        lambda singular, plural, n: _translations().ngettext(singular, plural, n),
        newstyle=True,
    )

    @app.before_request
    def remember_supported_locales() -> None:
        g._supported_locales = list(app.config["LANGUAGES"])

    @app.context_processor
    def inject_locale() -> dict[str, str]:
        return {"locale": select_locale(list(app.config["LANGUAGES"])).replace("_", "-")}
