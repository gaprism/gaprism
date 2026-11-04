"""Build the style guide: one static page with the tokens, the type and the real components.

    uv run python scripts/styleguide.py [FOLDER]

FOLDER defaults to var/styleguide (git-ignored). It receives index.html and, next to it, the
compiled stylesheet, the fonts and the logo files the page uses, so that the folder opens from disk
and can be handed to somebody else. The page is a document, not a route of the application: it is
rendered from assets/tokens.css, the committed stylesheet and the templates of the components, so it
shows what the application uses and changes when they change. Run `npm run build` first when
assets/ or the templates changed.

Exit status: 0 when the page was written, 2 when the arguments are wrong.
"""

from __future__ import annotations

import math
import re
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
TEMPLATES = ROOT / "app" / "templates"
STATIC = ROOT / "app" / "static"
PAGE = ASSETS / "styleguide.html"
DEFAULT_FOLDER = ROOT / "var" / "styleguide"
USAGE = "usage: styleguide.py [FOLDER]  (default: var/styleguide)"

COLOUR = re.compile(r"--color-([a-z-]+):\s*(#[0-9A-Fa-f]{6});")
RADIUS = re.compile(r"--radius-([a-z]+):\s*(\d+px);")
FALLBACK_GLYPH = "info"  # what the icon macro draws for a name it does not know
LOGO_FILES = {".svg", ".png", ".ico"}  # of app/static/brand, what the page shows and ships

TEXT, CONTROL = 4.5, 3.0  # WCAG 2.2 AA: text, and the borders of controls and the focus ring

# The sections of the page, in order: the contents list and the headings both come from here.
SECTIONS = (
    ("logo", "Logo and icons"),
    ("colour", "Colour"),
    ("shape", "Shape and depth"),
    ("type", "Type"),
    ("icons", "Icons"),
    ("buttons", "Buttons and links"),
    ("badges", "Badges"),
    ("messages", "Notices and empty states"),
    ("forms", "Forms"),
    ("tables", "Tables and tabs"),
    ("dialog", "Dialog"),
    ("menus", "Navigation and menus"),
)

# Every colour token: its group on the page and what it is for. A token without a line here is
# an error, so that nobody adds a colour that is not described.
TOKEN_ROLES = {
    "canvas": ("Surfaces and text", "Paper, the brand's background. The page behind everything."),
    "panel": ("Surfaces and text", "White. Cards, tables, menus and the top bar."),
    "subtle": (
        "Surfaces and text",
        "A quiet fill: hovered rows and controls, neutral badges, disabled controls.",
    ),
    "ink": (
        "Surfaces and text",
        "Graphite, the brand's text colour. Body text and headings; the wash behind dialogs.",
    ),
    "muted": ("Surfaces and text", "Secondary text: labels, captions and help text."),
    "line": ("Surfaces and text", "Hairlines between rows and around cards."),
    "action": (
        "Brand and controls",
        "Indigo, the brand's action colour. Primary buttons, links, the active tab, progress.",
    ),
    "action-hover": ("Brand and controls", "The primary button under the pointer."),
    "focus": ("Brand and controls", "The ring that shows where the keyboard is."),
    "selected": (
        "Brand and controls",
        "The fill of the current page in the navigation, and of the avatar.",
    ),
    "selected-ink": ("Brand and controls", "Text and icons on the selection fill."),
    "control": (
        "Brand and controls",
        "Borders of inputs and secondary buttons; they need 3 : 1 against what they sit on.",
    ),
    "danger": ("Status", "Destructive buttons and error messages."),
    "success": ("Status", "Confirmation text."),
    "critical": ("Severity", "Critical findings and failed scans."),
    "critical-bg": ("Severity", "The fill behind critical text, and behind danger notices."),
    "high": ("Severity", "High findings and failed checks."),
    "high-bg": ("Severity", "The fill behind high text."),
    "medium": ("Severity", "Medium findings, partial or unavailable results, warnings."),
    "medium-bg": ("Severity", "The fill behind medium text, and behind warnings."),
    "low": ("Severity", "Low findings. Slate, not blue, so that it is not taken for the brand."),
    "low-bg": ("Severity", "The fill behind low text."),
}

RADIUS_USES = {
    "sm": "Badges.",
    "md": "Buttons, inputs, menu items and notices.",
    "lg": "Cards, menus and dialogs.",
}

TONE_MEANINGS = {
    "critical": "The most serious findings; a scan that failed.",
    "high": "Serious findings; a check that failed.",
    "medium": "Needs a look: a partial or unavailable result, a warning.",
    "low": "A minor finding.",
    "info": "A neutral fact or state (Shared, Active, Signed), or work in progress.",
    "ok": "A check that passed, with a check mark. A state or a fact is not a result: use info.",
    "muted": "Nothing to report: no data, skipped, switched off, a label.",
}

# What the text of a pair is for. "white" is the colour of text on a filled button.
PAIRINGS_TEXT = (
    ("ink", "canvas", "Text on the page"),
    ("ink", "panel", "Text in cards, tables and menus; the ok badge"),
    ("ink", "subtle", "Text on a quiet fill"),
    ("ink", "selected", "Text on the selection fill"),
    ("muted", "canvas", "Secondary text on the page"),
    ("muted", "panel", "Secondary text in cards, tables and menus"),
    ("muted", "subtle", "Neutral badges and hovered rows"),
    ("muted", "selected", "Secondary text on the selection fill"),
    ("muted", "low-bg", "Secondary text on the low fill"),
    ("white", "action", "Primary button"),
    ("white", "action-hover", "Primary button under the pointer"),
    ("white", "danger", "Destructive button"),
    ("action", "canvas", "Links and the active tab on the page"),
    ("action", "panel", "Links and the active tab in cards"),
    ("action", "subtle", "Links on a quiet fill"),
    ("selected-ink", "selected", "The current page in the navigation"),
    ("danger", "canvas", "Error messages on the page"),
    ("danger", "panel", "Error messages in cards"),
    ("success", "canvas", "Confirmation on the page"),
    ("success", "panel", "Confirmation in cards"),
    ("critical", "critical-bg", "Critical badge"),
    ("high", "high-bg", "High badge"),
    ("medium", "medium-bg", "Medium badge and warnings"),
    ("low", "low-bg", "Low badge"),
)
PAIRINGS_CONTROL = (
    ("control", "panel", "Borders of inputs and secondary buttons in cards"),
    ("control", "canvas", "Borders of inputs and secondary buttons on the page"),
    ("control", "subtle", "Borders of controls on a quiet fill"),
    ("focus", "canvas", "Focus ring on the page"),
    ("focus", "panel", "Focus ring in cards"),
    ("focus", "subtle", "Focus ring on a quiet fill"),
    ("focus", "selected", "Focus ring on the selection fill"),
)


@dataclass(frozen=True)
class Pairing:
    """A foreground colour on a background colour, with the contrast it must reach."""

    foreground: str
    background: str
    use: str
    minimum: float


PAIRINGS = tuple(
    [Pairing(fg, bg, use, TEXT) for fg, bg, use in PAIRINGS_TEXT]
    + [Pairing(fg, bg, use, CONTROL) for fg, bg, use in PAIRINGS_CONTROL]
)


def read_tokens() -> dict[str, str]:
    """The colour tokens of assets/tokens.css, in the order of the file, with upper-case values."""
    css = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    return {name: value.upper() for name, value in COLOUR.findall(css)}


def read_radii() -> dict[str, str]:
    css = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    return dict(RADIUS.findall(css))


def _luminance(colour: str) -> float:
    linear = []
    for start in (1, 3, 5):
        value = int(colour[start : start + 2], 16) / 255
        linear.append(value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4)
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(first: str, second: str) -> float:
    """The WCAG contrast ratio of two colours written as ``#RRGGBB``."""
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _ratio(value: float) -> str:
    """Two decimals, rounded down: 4.499 must not read as 4.50."""
    return f"{math.floor(value * 100) / 100:.2f}"


def macro_choices(variable: str) -> dict[str, str]:
    """The ``{'name': 'classes'}`` dictionary that a macro of components/ui.html sets."""
    source = (TEMPLATES / "components" / "ui.html").read_text(encoding="utf-8")
    match = re.search(rf"set {variable} = \{{(.*?)\}}", source, re.S)
    if match is None:
        raise RuntimeError(f"components/ui.html no longer sets {variable}: update {__file__}")
    return dict(re.findall(r"'([a-z-]+)':\s*'([^']+)'", match.group(1)))


def glyph_names() -> list[str]:
    """The names the icon macro knows, and the glyph it falls back to."""
    source = (TEMPLATES / "components" / "ui.html").read_text(encoding="utf-8")
    names = list(dict.fromkeys(re.findall(r"name == '([a-z]+)'", source)))
    return names if FALLBACK_GLYPH in names else [*names, FALLBACK_GLYPH]


class _Specimen:
    """The person the account menu is shown for: an administrator, so that the menu is complete."""

    is_authenticated = True
    is_active = True
    is_anonymous = False
    email = "anna.meier@example.com"
    name: str | None = "Anna Meier"

    def __init__(self) -> None:
        from app.service.assessments import ADMIN_ROLE

        self.roles = (SimpleNamespace(name=ADMIN_ROLE),)

    def get_id(self) -> str:
        return "specimen"


class _Unnamed(_Specimen):
    """A member who has not said what they are called: the menu shows the address alone."""

    email = "tom.keller@example.com"
    name = None

    def __init__(self) -> None:
        self.roles = ()


def _project_on_path() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def _application() -> Flask:
    """An application that renders templates and nothing else: no provider keys, no database."""
    _project_on_path()
    from app import create_app
    from app.config import TestingConfig

    class StyleguideConfig(TestingConfig):
        CTLOGS_API_KEY = ""
        SHODAN_API_KEY = ""
        CERTSPOTTER_TOKEN = ""
        SQLALCHEMY_DATABASE_URI = "postgresql+psycopg://styleguide@127.0.0.1:9/none"

    return create_app(StyleguideConfig)


def _title(name: str) -> str:
    return name.replace("-bg", " fill").replace("-", " ").capitalize()


def _context() -> dict[str, Any]:
    from app.i18n import language_choices
    from app.service.findings import SEVERITIES, severity_label, severity_tone
    from app.service.host_view import summarize

    tokens = read_tokens()
    if set(tokens) != set(TOKEN_ROLES):
        undescribed = sorted(set(tokens) ^ set(TOKEN_ROLES))
        raise RuntimeError(
            f"tokens and TOKEN_ROLES differ: {undescribed}; describe them in {__file__}"
        )
    groups: dict[str, list[dict[str, str]]] = {}
    for name, hex_value in tokens.items():
        group, role = TOKEN_ROLES[name]
        groups.setdefault(group, []).append(
            {"name": name, "title": _title(name), "hex": hex_value, "role": role}
        )

    palette = {**tokens, "white": "#FFFFFF"}

    def rows(pairings: Sequence[Pairing]) -> list[dict[str, Any]]:
        found = []
        for pairing in pairings:
            ratio = contrast(palette[pairing.foreground], palette[pairing.background])
            found.append(
                {
                    "foreground": pairing.foreground,
                    "background": pairing.background,
                    "fg": palette[pairing.foreground],
                    "bg": palette[pairing.background],
                    "use": pairing.use,
                    "ratio": _ratio(ratio),
                    "minimum": f"{pairing.minimum:g}",
                    "passes": ratio >= pairing.minimum,
                }
            )
        return found

    tones = macro_choices("tones")
    return {
        # A value passed to the render call beats the context processor of Flask-WTF, which would
        # put a different token into the sign-out form on every build.
        "csrf_token": lambda: "specimen",
        "unnamed": _Unnamed(),
        "languages": language_choices(["en", "de_CH"], "en"),
        "sections": SECTIONS,
        "groups": [{"title": title, "tokens": found} for title, found in groups.items()],
        "text_pairings": rows([p for p in PAIRINGS if p.minimum == TEXT]),
        "control_pairings": rows([p for p in PAIRINGS if p.minimum == CONTROL]),
        "radii": [
            {"name": name, "size": size, "use": RADIUS_USES[name]}
            for name, size in read_radii().items()
        ],
        "glyphs": glyph_names(),
        "variants": list(macro_choices("variants")),
        "tones": [
            {"name": name, "classes": classes, "meaning": TONE_MEANINGS[name]}
            for name, classes in tones.items()
        ],
        "severities": [(severity_label(s), severity_tone(s)) for s in SEVERITIES],
        "outcomes": [
            summarize("example", status, None, {})
            for status in ("queued", "running", "ok", "no_data", "skipped", "unavailable", "error")
        ],
        "example_moment": datetime(2026, 11, 3, 8, 15, tzinfo=UTC),
    }


def render() -> str:
    """The page as HTML."""
    from flask import g, render_template_string

    app = _application()
    with app.test_request_context("/assessments/"):
        g._login_user = _Specimen()
        return render_template_string(PAGE.read_text(encoding="utf-8"), **_context())


def build(folder: Path) -> Path:
    """Write the page, the stylesheet, the fonts and the logos into ``folder``; return the page."""
    html = render()
    (folder / "static" / "css").mkdir(parents=True, exist_ok=True)
    (folder / "static" / "fonts").mkdir(parents=True, exist_ok=True)
    (folder / "static" / "brand").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STATIC / "css" / "app.css", folder / "static" / "css" / "app.css")
    for font in sorted((STATIC / "fonts").glob("*.woff2")):
        shutil.copyfile(font, folder / "static" / "fonts" / font.name)
    for logo in sorted((STATIC / "brand").iterdir()):
        if logo.suffix in LOGO_FILES:
            shutil.copyfile(logo, folder / "static" / "brand" / logo.name)
    page = folder / "index.html"
    page.write_bytes(html.encode("utf-8"))  # bytes: the same file on every platform
    return page


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) > 1 or any(arg.startswith("-") for arg in args):
        print(USAGE, file=sys.stderr)
        return 2
    page = build(Path(args[0]) if args else DEFAULT_FOLDER)
    print(f"Wrote {page}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
