"""The colour tokens carry the Gaprism brand and stay readable.

Paper, Graphite and Indigo come from the brand kit (identity statement, section 03); Signal
Teal is for diagrams. Severity and status colours stay apart from the brand colours, and every
text, control and focus pairing the components use reaches the contrast WCAG 2.2 AA asks for.
"""

import colorsys
import re

import pytest
from flask import Flask

from tests.helpers import PROJECT_ROOT

ASSETS = PROJECT_ROOT / "assets"
TOKEN = re.compile(r"--color-([a-z-]+):\s*(#[0-9A-Fa-f]{6});")

# (foreground, background): text and icons the components paint on those surfaces.
TEXT_PAIRS = [
    ("ink", "canvas"),
    ("ink", "panel"),
    ("ink", "subtle"),
    ("ink", "selected"),
    ("muted", "canvas"),
    ("muted", "panel"),
    ("muted", "subtle"),
    ("muted", "selected"),
    ("white", "action"),  # .btn-primary
    ("white", "action-hover"),
    ("white", "danger"),  # .btn-destructive
    ("action", "canvas"),  # .link, .tab
    ("action", "panel"),
    ("action", "subtle"),
    ("selected-ink", "selected"),  # .nav-link[aria-current=page]
    ("danger", "canvas"),
    ("danger", "panel"),
    ("success", "canvas"),
    ("success", "panel"),
    ("critical", "critical-bg"),  # severity badges
    ("high", "high-bg"),
    ("medium", "medium-bg"),
    ("low", "low-bg"),
    ("muted", "low-bg"),
    ("ok", "ok-bg"),
]

# Boundaries of controls and the keyboard focus ring need 3:1 against what they sit on.
NON_TEXT_PAIRS = [
    ("control", "panel"),
    ("control", "canvas"),
    ("control", "subtle"),
    ("focus", "canvas"),
    ("focus", "panel"),
    ("focus", "subtle"),
    ("focus", "selected"),
]

BADGE_TONES = ["critical", "high", "medium", "low", "info", "ok", "muted"]
BRAND_UTILITIES = {"bg-action", "text-action", "border-action", "bg-selected", "text-selected-ink"}


def _palette() -> dict[str, str]:
    css = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    tokens = {name: value.upper() for name, value in TOKEN.findall(css)}
    return {**tokens, "white": "#FFFFFF"}


def _channels(colour: str) -> tuple[int, int, int]:
    return int(colour[1:3], 16), int(colour[3:5], 16), int(colour[5:7], 16)


def _luminance(colour: str) -> float:
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in (channel / 255 for channel in _channels(colour))
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _hue_and_saturation(colour: str) -> tuple[float, float]:
    red, green, blue = (channel / 255 for channel in _channels(colour))
    hue, _lightness, saturation = colorsys.rgb_to_hls(red, green, blue)
    return hue * 360, saturation


def _badge_classes(tone: str) -> set[str]:
    app = Flask(__name__, template_folder=str(PROJECT_ROOT / "app" / "templates"))
    source = "{% from 'components/ui.html' import badge %}{{ badge('label', tone) }}"
    html = app.jinja_env.from_string(source).render(tone=tone)
    match = re.search(r'class="([^"]*)"', html)
    assert match is not None
    return set(match.group(1).split())


def test_the_interface_carries_the_brand_colours() -> None:
    palette = _palette()
    assert palette["canvas"] == "#F7F8FC"  # Paper
    assert palette["ink"] == "#172033"  # Graphite
    assert palette["action"] == "#4F46E5"  # Indigo


def test_signal_teal_stays_out_of_the_interface() -> None:
    assert "#45C8C0" not in _palette().values()


@pytest.mark.parametrize(("foreground", "background"), TEXT_PAIRS)
def test_text_reaches_4_5_to_1(foreground: str, background: str) -> None:
    palette = _palette()
    assert _contrast(palette[foreground], palette[background]) >= 4.5


@pytest.mark.parametrize(("foreground", "background"), NON_TEXT_PAIRS)
def test_control_borders_and_focus_reach_3_to_1(foreground: str, background: str) -> None:
    palette = _palette()
    assert _contrast(palette[foreground], palette[background]) >= 3


@pytest.mark.parametrize("status", ["critical", "high", "medium", "low", "ok", "danger", "success"])
def test_status_colours_do_not_look_like_the_brand(status: str) -> None:
    """Keep brand colours separate from severity and status colours (identity statement)."""
    palette = _palette()
    brand_hue, _ = _hue_and_saturation(palette["action"])
    hue, saturation = _hue_and_saturation(palette[status])
    apart = min(abs(hue - brand_hue), 360 - abs(hue - brand_hue))
    assert apart >= 30 or saturation <= 0.4, f"{status} {palette[status]} reads as Indigo"


@pytest.mark.parametrize("tone", BADGE_TONES)
def test_badge_tones_do_not_borrow_the_brand_colours(tone: str) -> None:
    assert not _badge_classes(tone) & BRAND_UTILITIES


def test_stylesheets_use_tokens_instead_of_colour_literals() -> None:
    for name in ("app.css", "report.css"):
        css = (ASSETS / name).read_text(encoding="utf-8")
        css = re.sub(r"var\(--color-[a-z-]+,\s*#[0-9A-Fa-f]{6}\)", "", css)  # print fallbacks
        css = re.sub(r"dialog::backdrop\s*\{[^}]*\}", "", css)  # the overlay wash, tested below
        assert not re.search(r"#[0-9A-Fa-f]{3,8}\b|\brgba?\(|\bhsla?\(", css), name


def test_report_fallback_colours_match_the_tokens() -> None:
    css = (ASSETS / "report.css").read_text(encoding="utf-8")
    fallbacks = re.findall(r"var\(--color-([a-z-]+),\s*(#[0-9A-Fa-f]{6})\)", css)
    assert fallbacks
    palette = _palette()
    for name, value in fallbacks:
        assert palette[name].lower() == value.lower(), name


def test_dialog_backdrop_is_a_wash_of_graphite() -> None:
    css = (ASSETS / "app.css").read_text(encoding="utf-8")
    match = re.search(r"dialog::backdrop\s*\{[^}]*rgb\((\d+) (\d+) (\d+) / \d+%\)", css)
    assert match is not None
    wash = tuple(int(part) for part in match.groups())
    assert wash == _channels(_palette()["ink"])


def test_the_committed_stylesheet_is_built_from_the_current_tokens() -> None:
    """app/static/css/app.css is committed; run ``npm run build`` after changing assets/."""
    built = (PROJECT_ROOT / "app" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    palette = _palette()
    for name in ("canvas", "ink", "action"):
        assert palette[name].lower() in built.lower(), name
