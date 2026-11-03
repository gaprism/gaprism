"""The style guide: one static page built from the tokens, the stylesheet and the real components.

scripts/styleguide.py writes it into a folder that opens from disk and can be handed to somebody
else. These tests read that page so that it cannot fall behind the interface it describes: a new
token, badge tone, button variant or icon shows up in it, or the build fails.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.helpers import PROJECT_ROOT

SCRIPT = PROJECT_ROOT / "scripts" / "styleguide.py"
ASSETS = PROJECT_ROOT / "assets"
TEMPLATES = PROJECT_ROOT / "app" / "templates"
STATIC = PROJECT_ROOT / "app" / "static"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("styleguide", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["styleguide"] = module  # a dataclass looks its own module up
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def styleguide() -> ModuleType:
    return load_script()


@pytest.fixture(scope="module")
def built(styleguide: ModuleType, tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("styleguide")
    styleguide.build(folder)
    return folder


@pytest.fixture(scope="module")
def page(built: Path) -> str:
    return (built / "index.html").read_text(encoding="utf-8")


def _macro_choices(variable: str) -> dict[str, str]:
    """The ``{'name': 'classes'}`` dictionary a macro of components/ui.html sets."""
    source = (TEMPLATES / "components" / "ui.html").read_text(encoding="utf-8")
    match = re.search(rf"set {variable} = \{{(.*?)\}}", source, re.S)
    assert match is not None, variable
    return dict(re.findall(r"'([a-z-]+)':\s*'([^']+)'", match.group(1)))


def _tokens() -> dict[str, str]:
    css = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    return {
        name: value.upper() for name, value in re.findall(r"--color-([a-z-]+):\s*(#\w{6});", css)
    }


def _classes_in(html: str) -> set[str]:
    return {name for value in re.findall(r'class="([^"]*)"', html) for name in value.split()}


def _classes_defined_in(css: str) -> set[str]:
    """Class names of a compiled stylesheet, with the escapes of Tailwind's selectors removed."""
    return {
        re.sub(r"\\(.)", r"\1", name) for name in re.findall(r"\.((?:\\.|[A-Za-z0-9_-])+)", css)
    }


def test_the_guide_comes_with_the_stylesheet_and_the_fonts_it_uses(built: Path, page: str) -> None:
    assert (built / "static" / "css" / "app.css").read_bytes() == (
        STATIC / "css" / "app.css"
    ).read_bytes()
    fonts = sorted(path.name for path in (STATIC / "fonts").glob("*.woff2"))
    assert fonts and fonts == sorted(path.name for path in (built / "static" / "fonts").iterdir())
    assert '<link rel="stylesheet" href="static/css/app.css">' in page


def test_every_colour_token_is_shown_with_its_name_and_value(page: str) -> None:
    for name, value in _tokens().items():
        assert f"--color-{name}" in page, name
        assert value in page.upper(), name


def test_every_colour_token_has_a_role(styleguide: ModuleType) -> None:
    """A token that nobody described cannot be used well: say what it is for in TOKEN_ROLES."""
    assert set(styleguide.TOKEN_ROLES) == set(_tokens())


def test_every_radius_is_shown(page: str) -> None:
    css = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    radii = re.findall(r"--radius-([a-z]+):\s*(\d+px);", css)
    assert radii
    for name, size in radii:
        assert f"--radius-{name}" in page and size in page, name


def test_every_badge_tone_is_shown(page: str) -> None:
    tones = _macro_choices("tones")
    assert {"critical", "high", "medium", "low", "info", "ok", "muted"} <= set(tones)
    for tone, classes in tones.items():
        assert f'class="badge {classes}"' in page, tone
        assert f"<code>{tone}</code>" in page, tone


def test_every_button_variant_is_shown(page: str) -> None:
    variants = _macro_choices("variants")
    assert {"primary", "secondary", "quiet", "destructive"} <= set(variants)
    for variant, classes in variants.items():
        assert f'class="btn {classes}"' in page, variant


def test_every_icon_is_shown_by_name(page: str) -> None:
    source = (TEMPLATES / "components" / "ui.html").read_text(encoding="utf-8")
    names = set(re.findall(r"name == '([a-z]+)'", source)) | {"info"}  # info is the fallback glyph
    assert {"grid", "shield", "check", "user", "menu", "chevron"} <= names
    for name in names:
        assert f"<code>{name}</code>" in page, name


@pytest.mark.parametrize(
    ("label", "classes"),
    [
        ("Critical", "bg-critical-bg text-critical"),
        ("High", "bg-high-bg text-high"),
        ("Medium", "bg-medium-bg text-medium"),
        ("Low", "bg-low-bg text-low"),
        ("Informational", "bg-subtle text-muted"),
    ],
)
def test_the_severities_look_as_they_do_in_the_findings(
    page: str, label: str, classes: str
) -> None:
    assert f'<span class="badge {classes}">{label}</span>' in page


@pytest.mark.parametrize(
    ("label", "classes"),
    [
        ("Queued", "bg-subtle text-muted"),
        ("Running", "bg-subtle text-muted"),
        ("Done", "bg-ok-bg text-ok"),
        ("No data", "bg-subtle text-muted"),
        ("Skipped", "bg-subtle text-muted"),
        ("Unavailable", "bg-medium-bg text-medium"),
        ("Failed", "bg-high-bg text-high"),
    ],
)
def test_the_outcomes_of_a_check_look_as_they_do_on_the_host_page(
    page: str, label: str, classes: str
) -> None:
    assert f'<span class="badge {classes}">{label}</span>' in page


def test_the_account_menu_is_the_one_the_pages_use(page: str) -> None:
    menu = re.search(r'<ul class="menu-panel[^"]*">(.*?)</ul>', page, re.S)
    assert menu is not None
    for part in ('class="menu-head"', "Signed in as", "Administrator", "Password", "Two-factor"):
        assert part in menu.group(1), part
    assert re.search(r'<button class="menu-item" type="submit">Sign out</button>', menu.group(1))


def test_the_three_looks_of_ok_sit_side_by_side(page: str, styleguide: ModuleType) -> None:
    looks = styleguide.ok_looks()
    assert [look.key for look in looks] == ["A", "B", "C"]
    for look in looks:
        assert f'id="ok-{look.key.lower()}"' in page
        assert look.foreground in page and look.background in page


def test_every_look_of_ok_is_readable(styleguide: ModuleType) -> None:
    for look in styleguide.ok_looks():
        assert styleguide.contrast(look.foreground, look.background) >= 4.5, look.key


def test_contrast_follows_the_wcag_formula(styleguide: ModuleType) -> None:
    assert styleguide.contrast("#000000", "#FFFFFF") == pytest.approx(21)
    assert styleguide.contrast("#FFFFFF", "#FFFFFF") == pytest.approx(1)
    assert styleguide.contrast("#767676", "#FFFFFF") == pytest.approx(4.54, abs=0.01)  # the AA grey


def test_every_pairing_of_colours_reaches_its_minimum(styleguide: ModuleType, page: str) -> None:
    tokens = {**styleguide.read_tokens(), "white": "#FFFFFF"}
    assert len(styleguide.PAIRINGS) >= 30
    for pairing in styleguide.PAIRINGS:
        ratio = styleguide.contrast(tokens[pairing.foreground], tokens[pairing.background])
        assert ratio >= pairing.minimum, (pairing.foreground, pairing.background, ratio)
        assert f"{pairing.foreground} on {pairing.background}" in page


def test_the_headings_of_the_guide_are_the_ones_the_base_styles_set(page: str) -> None:
    css = (ASSETS / "app.css").read_text(encoding="utf-8")
    for tag in ("h1", "h2", "h3"):
        base = re.search(rf"\b{tag} \{{ @apply ([^;]+);", css)
        assert base is not None, tag
        specimen = re.search(rf'data-type="{tag}" class="([^"]*)"', page)
        assert specimen is not None, tag
        assert set(specimen.group(1).split()) == set(base.group(1).split()), tag


def test_the_contents_list_every_section_in_order(page: str) -> None:
    contents = re.search(r'<nav aria-label="Contents".*?</nav>', page, re.S)
    assert contents is not None
    linked = re.findall(r'href="#([a-z-]+)"', contents.group(0))
    sections = re.findall(r'<section id="([a-z-]+)"', page)
    assert len(sections) >= 10 and linked == sections


def test_the_guide_is_a_document_without_scripts_or_other_origins(page: str) -> None:
    assert "<script" not in page
    assert not re.search(r"(https?:)?//[a-z0-9]", page, re.I)
    assert page.count("<link ") == 1


def test_the_guide_uses_only_classes_the_stylesheet_defines(built: Path, page: str) -> None:
    """The stylesheet is committed: after changing assets/styleguide.html run ``npm run build``."""
    defined = _classes_defined_in((built / "static" / "css" / "app.css").read_text("utf-8"))
    missing = sorted(_classes_in(page) - defined)
    assert not missing, f"not in app/static/css/app.css: {missing}; run `npm run build`"


def test_building_the_guide_twice_gives_the_same_page(
    styleguide: ModuleType, page: str, tmp_path: Path
) -> None:
    styleguide.build(tmp_path)
    assert (tmp_path / "index.html").read_text(encoding="utf-8") == page


def test_the_command_line_writes_the_guide(tmp_path: Path) -> None:
    target = tmp_path / "guide"
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(target)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert (target / "index.html").is_file()
    assert "index.html" in done.stdout


def test_the_command_line_refuses_more_than_one_folder(tmp_path: Path) -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "a"), str(tmp_path / "b")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2
    assert "usage" in done.stderr.lower()
