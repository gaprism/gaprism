"""The logo and the icons: the kit's files, used as supplied, and where the pages show them.

The files in app/static/brand come from the Gaprism logo kit (direction C). They are served from the
application's own origin, so each one is plain vector artwork or a raster file and nothing else.
The sidebar shows the lockup when it is open and the symbol when it is a rail, the top bar shows
the symbol, and every document names the icons and the colour of the browser's own bar.
"""

from __future__ import annotations

import re
import struct

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from tests.helpers import PROJECT_ROOT, create_user, login_as

ASSETS = PROJECT_ROOT / "assets"
STATIC = PROJECT_ROOT / "app" / "static"
BRAND = STATIC / "brand"
LOCKUP = "gaprism-logo-horizontal-color.svg"
SYMBOL = "gaprism-symbol-color.svg"
LOGO_COLOURS = {"#4F46E5", "#172033"}  # Indigo for the symbol, Graphite for the lettering

ICON_TAGS = [
    '<link rel="icon" href="/static/brand/favicon.ico" sizes="16x16 32x32 48x48">',
    '<link rel="icon" href="/static/brand/favicon.svg" type="image/svg+xml">',
    '<link rel="apple-touch-icon" href="/static/brand/apple-touch-icon.png">',
]
THEME_COLOUR = '<meta name="theme-color" content="#FFFFFF">'


def attributes(tag: str) -> dict[str, str]:
    return dict(re.findall(r'([a-z-]+)="([^"]*)"', tag))


def aspect(name: str) -> float:
    """Height over width of a logo file, from its own viewBox."""
    box = re.search(r'viewBox="0 0 (\d+) (\d+)"', (BRAND / name).read_text(encoding="utf-8"))
    assert box is not None, name
    return int(box.group(2)) / int(box.group(1))


def test_the_brand_folder_holds_the_logo_and_the_icons() -> None:
    names = {path.name for path in BRAND.iterdir()}
    wanted = {LOCKUP, SYMBOL, "favicon.svg", "favicon.ico", "apple-touch-icon.png", "README.md"}
    assert wanted <= names


@pytest.mark.parametrize("name", [LOCKUP, SYMBOL, "favicon.svg"])
def test_a_logo_file_is_plain_vector_artwork(name: str) -> None:
    """It is served from our own origin: no script, no reference, no bitmap, only logo colours."""
    svg = (BRAND / name).read_text(encoding="utf-8")
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ')
    body = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for forbidden in (
        "<script",
        "<foreignObject",
        "<image",
        "<style",
        "<use",
        "href",
        "url(",
        "http",
        "data:",
        "@import",
    ):
        assert forbidden not in body, forbidden
    assert not re.search(r"\son[a-z]+\s*=", body), "an event handler"
    colours = {colour.upper() for colour in re.findall(r'fill="(#[0-9A-Fa-f]{6})"', svg)}
    assert colours and colours <= LOGO_COLOURS


def test_the_touch_icon_is_a_180_px_png() -> None:
    data = (BRAND / "apple-touch-icon.png").read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", data[16:24]) == (180, 180)


def test_the_ico_file_holds_16_32_and_48_px() -> None:
    data = (BRAND / "favicon.ico").read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1)
    sizes = {(data[6 + 16 * i] or 256, data[7 + 16 * i] or 256) for i in range(count)}
    assert sizes == {(16, 16), (32, 32), (48, 48)}


def test_the_icon_files_are_served(client: FlaskClient) -> None:
    served = {
        "favicon.ico": "image/",
        "favicon.svg": "image/svg+xml",
        "apple-touch-icon.png": "image/png",
        LOCKUP: "image/svg+xml",
        SYMBOL: "image/svg+xml",
    }
    for name, kind in served.items():
        response = client.get(f"/static/brand/{name}")
        assert response.status_code == 200 and response.mimetype.startswith(kind), name


def test_every_kind_of_page_names_the_icons_and_the_colour_of_the_browser_bar(
    client: FlaskClient, db_session: Session
) -> None:
    sign_in = client.get("/auth/login").get_data(as_text=True)
    error = client.get("/no-such-page").get_data(as_text=True)
    login_as(client, create_user(db_session))
    signed_in = client.get("/assessments/").get_data(as_text=True)
    for page in (sign_in, error, signed_in):
        head = page.split("</head>", 1)[0]
        for tag in (*ICON_TAGS, THEME_COLOUR):
            assert tag in head, tag


def test_the_colour_of_the_browser_bar_is_the_colour_of_the_top_bar() -> None:
    tokens = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    panel = re.search(r"--color-panel:\s*(#[0-9A-Fa-f]{6});", tokens)
    assert panel is not None
    assert THEME_COLOUR == f'<meta name="theme-color" content="{panel.group(1).upper()}">'


def test_the_sidebar_shows_the_lockup_and_the_symbol_for_the_rail(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))
    page = client.get("/assessments/").get_data(as_text=True)
    sidebar = re.search(r'<aside class="sidebar"[^>]*>(.*?)</aside>', page, re.S)
    assert sidebar is not None
    brand = re.search(
        r'<a href="/assessments/" class="brand"[^>]*>(.*?)</a>', sidebar.group(1), re.S
    )
    assert brand is not None
    assert "<svg" not in brand.group(1), "the placeholder icon is still there"
    images = {
        attributes(tag)["class"]: attributes(tag)
        for tag in re.findall(r"<img [^>]*>", brand.group(1))
    }
    assert set(images) == {"brand-lockup", "brand-symbol"}
    lockup, symbol = images["brand-lockup"], images["brand-symbol"]
    assert lockup["src"] == f"/static/brand/{LOCKUP}"
    assert symbol["src"] == f"/static/brand/{SYMBOL}"
    # The kit's minima for screens: 160 px for the horizontal logo, 24 px for the symbol; and the
    # size attributes keep the proportions of the file, so that the logo is never stretched.
    assert int(lockup["width"]) >= 160
    assert abs(int(lockup["width"]) * aspect(LOCKUP) - int(lockup["height"])) <= 1
    assert int(symbol["width"]) >= 24 and symbol["width"] == symbol["height"]
    # Only one of them is shown at a time, so each carries the name for a screen reader.
    assert lockup["alt"] == symbol["alt"] == "Gaprism"


def test_the_top_bar_shows_the_symbol_and_links_home(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))
    page = client.get("/assessments/").get_data(as_text=True)
    bar = re.search(r"<header[^>]*>(.*?)</header>", page, re.S)
    assert bar is not None
    brand = re.search(
        r'<a href="/assessments/" class="topbar-brand[^"]*">(.*?)</a>', bar.group(1), re.S
    )
    assert brand is not None
    assert "<svg" not in brand.group(1), "the placeholder icon is still there"
    image = attributes(re.findall(r"<img [^>]*>", brand.group(1))[0])
    assert image["src"] == f"/static/brand/{SYMBOL}" and image["alt"] == "Gaprism"
    assert int(image["width"]) >= 24 and image["width"] == image["height"]


def test_the_stylesheet_shows_the_lockup_in_the_open_sidebar_and_the_symbol_in_the_rail() -> None:
    """Run ``npm run build`` after changing assets/app.css: the stylesheet is committed."""
    css = re.sub(r"\s+", "", (STATIC / "css" / "app.css").read_text(encoding="utf-8"))
    assert ".brand-lockup{display:none}" in css
    assert "html:not([data-nav=rail]).brand-lockup{display:block}" in css
    assert "html:not([data-nav=rail]).brand-symbol{display:none}" in css
