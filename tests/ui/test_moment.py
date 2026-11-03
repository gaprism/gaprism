"""The moment macro of components/ui.html: a time in UTC that breaks only between date and time.

Without it a column of dates wraps inside the date ("2026-11- / 03 08:15 / UTC") as soon as the
table is short of room.
"""

from datetime import UTC, datetime

from flask import Flask

from tests.helpers import PROJECT_ROOT


def render_moment(value: datetime) -> str:
    app = Flask(__name__, template_folder=str(PROJECT_ROOT / "app" / "templates"))
    source = "{% from 'components/ui.html' import moment %}{{ moment(value) }}"
    return app.jinja_env.from_string(source).render(value=value).strip()


def test_a_moment_is_in_utc_and_breaks_only_between_the_date_and_the_time() -> None:
    html = render_moment(datetime(2026, 11, 3, 8, 15, 42, tzinfo=UTC))
    assert html == (
        '<time datetime="2026-11-03T08:15:42+00:00">'
        '<span class="whitespace-nowrap">2026-11-03</span> '
        '<span class="whitespace-nowrap">08:15 UTC</span></time>'
    )
