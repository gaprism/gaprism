"""The text field of components/forms.html: the label, the help and the error belong to the input.

An input may point at help or error text only when that text is on the page: a reference to
nothing tells a screen reader nothing.
"""

import re

from flask import Flask
from werkzeug.datastructures import MultiDict
from wtforms import Form, StringField, validators

from tests.helpers import PROJECT_ROOT, attributes


class Sample(Form):
    name = StringField("Name", [validators.DataRequired("Enter a name.")])


def render_field(*, errors: bool = False, **options: object) -> str:
    app = Flask(__name__, template_folder=str(PROJECT_ROOT / "app" / "templates"))
    form = Sample(MultiDict())
    if errors:
        assert not form.validate()
    source = (
        "{% from 'components/forms.html' import text_field %}"
        "{{ text_field(field, 'Name', **options) }}"
    )
    return app.jinja_env.from_string(source).render(field=form.name, options=options)


def input_of(html: str) -> dict[str, str]:
    match = re.search(r"<input [^>]*>", html)
    assert match is not None
    return attributes(match.group(0))


def test_a_field_without_help_or_errors_points_at_nothing() -> None:
    field = input_of(render_field())
    assert "aria-describedby" not in field and field["aria-invalid"] == "false"


def test_the_help_is_pointed_at() -> None:
    html = render_field(help="Your name.")
    assert input_of(html)["aria-describedby"] == "name-help"
    assert '<p class="field-help" id="name-help">Your name.</p>' in html


def test_an_error_is_pointed_at_and_marks_the_input_invalid() -> None:
    html = render_field(errors=True)
    field = input_of(html)
    assert field["aria-describedby"] == "name-error" and field["aria-invalid"] == "true"
    assert '<p class="text-sm text-danger" id="name-error">Enter a name.</p>' in html


def test_help_and_error_are_both_pointed_at() -> None:
    html = render_field(errors=True, help="Your name.")
    assert input_of(html)["aria-describedby"] == "name-help name-error"
    ids = set(re.findall(r'id="([^"]+)"', html))
    assert {"name-help", "name-error"} <= ids


def test_more_attributes_reach_the_input() -> None:
    field = input_of(render_field(attrs={"inputmode": "numeric", "value": ""}, autocomplete="x"))
    assert field["inputmode"] == "numeric" and field["value"] == "" and field["autocomplete"] == "x"
