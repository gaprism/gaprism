"""Flask-Security words its messages through its own translation domain, and without Flask-Babel
that domain hands every text back as it is, whatever the language. The application puts its own
catalogue in its place, so that the messages of the sign-in, the password and the two-factor
screens (app/config.py words the ones that are ours) are in the language of the page."""

from __future__ import annotations

import flask_security.core as flask_security_core
import flask_security.forms as flask_security_forms
import pytest
from flask import Flask
from flask_security.utils import get_message

from app.config import BaseConfig
from tests.helpers import Marked, load_script

tr = load_script("translations")


def test_a_message_of_flask_security_goes_through_the_catalogue(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    with app.test_request_context("/"):
        message, category = get_message("PASSWORD_CHANGE")
        filled, _category = get_message("PASSWORD_INVALID_LENGTH", length=12)
    assert message == "[xx] Your password has been changed."
    assert category == "success"
    assert filled == "[xx] The new password is too short. Use at least 12 characters."


def test_the_templates_of_flask_security_use_the_same_catalogue(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    with app.test_request_context("/"):
        assert app.jinja_env.globals["_fsdomain"]("Some text") == "[xx] Some text"


def test_in_english_a_message_is_the_one_the_application_words(app: Flask) -> None:
    with app.test_request_context("/"):
        message, _category = get_message("PASSWORD_CHANGE")
    assert message == "Your password has been changed."


def test_the_names_of_the_second_factor_methods_are_not_sentences_of_ours() -> None:
    """The library hands the templates the name of the method it translated, and ours compare it as
    text (``chosen_method == 'authenticator'``). A catalogue entry for one of these words would
    break the two-factor screens in that language, so none may exist."""
    names = {name for name in flask_security_forms._setup_methods_xlate.values() if name}
    listed = {message.id for message in tr.read_catalogue(tr.TEMPLATE) if message.id}
    assert "authenticator" in names
    assert not names & listed


MESSAGES = sorted(name for name in vars(BaseConfig) if name.startswith("SECURITY_MSG_"))


@pytest.mark.parametrize("name", MESSAGES)
def test_every_message_the_application_words_is_listed_in_the_template(name: str) -> None:
    """The library's own words are in no extraction, so each one that is worded in the
    configuration is wrapped in N_ there; a new one without N_ would stay English."""
    listed = {message.id for message in tr.read_catalogue(tr.TEMPLATE) if message.id}
    text, category = getattr(BaseConfig, name)
    assert text in listed, f"{name} is not marked with N_ in app/config.py"
    assert category in {"error", "success", "info", "warning"}


LISTED_ONLY = [
    "UNAUTHENTICATED",
    "UNAUTHORIZED",
    "ANONYMOUS_USER_REQUIRED",
    "DISABLED_ACCOUNT",
    "USER_DOES_NOT_EXIST",
    "EMAIL_NOT_PROVIDED",
    "INVALID_EMAIL_ADDRESS",
    "INVALID_REDIRECT",
]


@pytest.mark.parametrize("key", LISTED_ONLY)
def test_a_message_that_is_only_listed_is_worded_as_the_library_words_it(key: str) -> None:
    """These are listed so that they can be translated; listing must not change the English."""
    assert getattr(BaseConfig, f"SECURITY_MSG_{key}") == flask_security_core._default_messages[key]
