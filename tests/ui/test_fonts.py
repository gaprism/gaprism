"""The type: IBM Plex, served from our own origin, with the licences it asks for."""

import re

import pytest

from tests.helpers import PROJECT_ROOT

ASSETS = PROJECT_ROOT / "assets"
STATIC = PROJECT_ROOT / "app" / "static"
FACE = re.compile(r"@font-face\s*\{([^}]*)\}")

# The faces the interface uses: Sans for text (regular, labels, headings) and Mono for domains,
# addresses and identifiers (also in headings, hence the heavier one).
FACES = {
    ("IBM Plex Sans", "400"),
    ("IBM Plex Sans", "500"),
    ("IBM Plex Sans", "600"),
    ("IBM Plex Mono", "400"),
    ("IBM Plex Mono", "600"),
}


def _declarations(block: str) -> dict[str, str]:
    pairs = (part.split(":", 1) for part in block.split(";") if ":" in part)
    return {name.strip(): value.strip() for name, value in pairs}


def _faces(name: str) -> list[dict[str, str]]:
    css = (ASSETS / name).read_text(encoding="utf-8")
    return [_declarations(block) for block in FACE.findall(css)]


def _files(faces: list[dict[str, str]]) -> set[str]:
    return {
        match.group(1)
        for face in faces
        if (match := re.search(r'url\("\.\./fonts/([^"]+)"\)', face["src"]))
    }


def test_the_font_tokens_name_plex_first() -> None:
    tokens = (ASSETS / "tokens.css").read_text(encoding="utf-8")
    sans = re.search(r"--font-sans:\s*([^;]+);", tokens)
    mono = re.search(r"--font-mono:\s*([^;]+);", tokens)
    assert sans is not None and sans.group(1).startswith('"IBM Plex Sans", ')
    assert mono is not None and mono.group(1).startswith('"IBM Plex Mono", ')


def test_the_stylesheet_declares_the_plex_faces() -> None:
    faces = _faces("app.css")
    declared = {(f["font-family"].strip("\"'"), f["font-weight"]) for f in faces}
    assert declared == FACES
    assert all(f["font-style"] == "normal" and f["font-display"] == "swap" for f in faces)


def test_every_face_points_at_a_woff2_file_that_is_there() -> None:
    files = _files(_faces("app.css"))
    assert len(files) == len(FACES)
    for name in files:
        path = STATIC / "fonts" / name
        assert path.is_file(), name
        assert path.read_bytes()[:4] == b"wOF2", f"{name} is not a woff2 file"


def test_no_other_font_is_left_behind() -> None:
    shipped = {path.name for path in (STATIC / "fonts").iterdir()}
    assert shipped == _files(_faces("app.css"))


@pytest.mark.parametrize("name", ["ibm-plex-sans.txt", "ibm-plex-mono.txt"])
def test_the_licence_of_each_font_is_shipped(name: str) -> None:
    text = (STATIC / "licenses" / name).read_text(encoding="utf-8").upper()
    assert "SIL OPEN FONT LICENSE" in text and "IBM" in text


def test_the_report_uses_the_same_type_as_the_pages() -> None:
    css = (ASSETS / "report.css").read_text(encoding="utf-8")
    assert not FACE.search(css) and "Evidence Sans" not in css and "Inter" not in css
    assert re.search(r"\.report-body\s*\{[^}]*font-family:\s*var\(--font-sans\)", css)


def test_tables_use_tabular_numerals() -> None:
    css = (ASSETS / "app.css").read_text(encoding="utf-8")
    table = re.search(r"\.data-table\s*\{([^}]*)\}", css)
    assert table is not None and "tabular-nums" in table.group(1)


def test_the_committed_stylesheet_carries_the_faces() -> None:
    """app/static/css/app.css is committed; run ``npm run build`` after changing assets/."""
    built = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    assert "IBM Plex Sans" in built and "ibm-plex-mono-latin-600-normal.woff2" in built
