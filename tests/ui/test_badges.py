"""The badge: words plus colour, and a check mark only where a check passed.

A passed check reads as ink on white with a check mark, so that only the problems carry colour.
Facts and states (Shared, Active, Accepted, Signed, Locked) are not results and use a neutral tone;
the pages that show them are tested next to their other content (``badge_classes``).
"""

import re

import pytest

from tests.helpers import NEUTRAL_BADGE, PROJECT_ROOT, render_badge

ASSETS = PROJECT_ROOT / "assets"
STATIC = PROJECT_ROOT / "app" / "static"
CHECK_MARK = '<path d="m5 12 4 4L19 6"/>'
OTHER_TONES = ["critical", "high", "medium", "low", "info", "muted"]


def test_the_ok_badge_is_ink_on_white_with_a_check_mark() -> None:
    html = render_badge("Not listed", "ok")
    assert html.startswith('<span class="badge bg-panel text-ink"><svg')
    assert CHECK_MARK in html
    assert html.endswith("</svg>Not listed</span>")


def test_the_check_mark_is_decoration_and_the_words_are_the_label() -> None:
    html = render_badge("Not listed", "ok")
    assert 'aria-hidden="true"' in html
    assert re.sub(r"<[^>]*>", "", html).strip() == "Not listed"


@pytest.mark.parametrize("tone", OTHER_TONES)
def test_no_other_tone_has_an_icon(tone: str) -> None:
    assert "<svg" not in render_badge("Label", tone)


def test_an_unknown_tone_is_a_plain_neutral_badge() -> None:
    assert render_badge("Label", "nonsense") == f'<span class="badge {NEUTRAL_BADGE}">Label</span>'


def test_the_icon_of_a_badge_is_as_small_as_its_words() -> None:
    """Without the rule the 18 px icon would tower over 12 px text."""
    source = (ASSETS / "app.css").read_text(encoding="utf-8")
    assert re.search(r"\.badge > svg \{ @apply size-3\.5; \}", source)
    built = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    assert ".badge>svg" in re.sub(r"\s+", "", built), "run `npm run build`"
