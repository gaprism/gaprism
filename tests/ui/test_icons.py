"""The icons are line icons on a 24 px grid with a 2 px stroke and round ends and corners."""

import pytest
from flask import Flask

from tests.helpers import PROJECT_ROOT

GLYPHS = [
    "grid",
    "hosts",
    "shield",
    "globe",
    "check",
    "users",
    "user",
    "menu",
    "collapse",
    "chevron",
    "info",
]


def _icon(name: str) -> str:
    app = Flask(__name__, template_folder=str(PROJECT_ROOT / "app" / "templates"))
    source = "{% from 'components/ui.html' import icon %}{{ icon(name) }}"
    return app.jinja_env.from_string(source).render(name=name)


@pytest.mark.parametrize("name", GLYPHS)
def test_icons_follow_the_line_icon_rules_of_the_brand(name: str) -> None:
    svg = _icon(name)
    assert 'viewBox="0 0 24 24"' in svg
    assert 'fill="none"' in svg and 'stroke="currentColor"' in svg
    assert 'stroke-width="2"' in svg
    # Round ends also make the dots of "M7 6h.01" visible.
    assert 'stroke-linecap="round"' in svg and 'stroke-linejoin="round"' in svg
    assert 'aria-hidden="true"' in svg  # decorative: the words next to it name the action
