"""The validators that refuse in our words (app/forms.py): the sentence is ours, and it is looked up
when the form refuses, because the validators are built once and the language is the request's."""

from __future__ import annotations

import re

import pytest
from werkzeug.datastructures import MultiDict
from wtforms import Form, StringField

from app.forms import AtMost, Entered
from tests.helpers import Marked, attributes


class Sample(Form):
    name = StringField(
        validators=[Entered("Enter a name."), AtMost(5, "A name has at most %(max)d characters.")]
    )


def refused(**data: str) -> list[str]:
    form = Sample(MultiDict(data))
    form.validate()
    return list(form.name.errors)


@pytest.mark.parametrize("entered", ["", "   ", "\t\n"])
def test_an_empty_or_blank_entry_is_refused_with_what_to_enter(entered: str) -> None:
    assert refused(name=entered) == ["Enter a name."]
    assert refused() == ["Enter a name."]  # nothing sent at all


def test_a_long_entry_is_refused_with_the_limit_filled_in() -> None:
    assert refused(name="abcdef") == ["A name has at most 5 characters."]
    assert refused(name="abcde") == []  # exactly the limit is fine


def test_a_good_entry_passes() -> None:
    assert refused(name="Anna") == []


def test_the_input_keeps_the_attributes_the_library_validators_would_have_set() -> None:
    tag = re.search(r"<input [^>]*>", str(Sample(MultiDict()).name()))
    assert tag is not None
    assert " required" in tag.group(0) and attributes(tag.group(0))["maxlength"] == "5"


def test_the_sentences_are_translated_when_the_form_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert refused(name="") == ["Enter a name."]  # before the language is chosen
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    assert refused(name="") == ["[xx] Enter a name."]
    assert refused(name="abcdef") == ["[xx] A name has at most 5 characters."]
