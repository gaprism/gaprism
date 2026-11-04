"""No file of the repository holds an invisible or a control character.

Some characters cannot be seen and still change what a line means. A byte order mark inside a
string made CSV_BOM look empty (an editor had replaced the escape that was typed with the character
it stands for); a zero-width space makes two names that look the same differ; a right-to-left
override makes the code on the screen differ from the code that runs ("Trojan Source").

The test reads every file that git tracks and every new file that is not ignored (so a mistake fails
here before it is committed) and fails on each character of these Unicode categories:

- Cc, controls, except the line feed, the carriage return and the tab;
- Cf, format characters (the byte order mark, the zero-width space, the bidirectional controls and
  the soft hyphen among them), except the zero-width joiner and non-joiner, which some scripts need;
- Cs, surrogates, and Co, private use.

It names the file, the line and the column (both from 1) and the character. No list of exceptions
exists: no file keeps such a character. A file is skipped when git would call it binary (it holds a
NUL byte, as the fonts and images do), when it lives below node_modules, or when it is deleted from
the working tree but still in the index.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest

from tests.helpers import PROJECT_ROOT

GIT = shutil.which("git")
needs_a_checkout = pytest.mark.skipif(
    GIT is None or not (PROJECT_ROOT / ".git").exists(),
    reason="needs git and a checkout of the repository: git lists the files",
)

# The categories that hide in text, with the word that names them in a report.
FORBIDDEN = {"Cc": "control", "Cf": "format", "Cs": "surrogate", "Co": "private use"}
ALLOWED = {
    "\n",  # what every text file is made of
    "\r",
    "\t",
    "\N{ZERO WIDTH NON-JOINER}",  # Persian and others cannot be spelled without these two
    "\N{ZERO WIDTH JOINER}",
}
# Printable ASCII cannot be forbidden, so only what is not printable ASCII is looked at.
CANDIDATE = re.compile(r"[^\x20-\x7e]")

HINT = (
    "Write such a character as an escape, never typed or pasted:",
    r'    CSV_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"   or   chr(0xFEFF)',
    "A byte order mark at the start of a file goes: save the file as UTF-8 without BOM.",
)


def hidden_characters(text: str) -> Iterator[tuple[int, int, str]]:
    """The forbidden characters of ``text`` as (line, column, character), counted from 1."""
    for match in CANDIDATE.finditer(text):
        char = match.group()
        if char in ALLOWED or unicodedata.category(char) not in FORBIDDEN:
            continue
        start = match.start()
        yield text.count("\n", 0, start) + 1, start - text.rfind("\n", 0, start), char


def describe(char: str) -> str:
    """``U+200B ZERO WIDTH SPACE (format)``; controls and private-use characters have no name."""
    name = unicodedata.name(char, "")
    kind = FORBIDDEN[unicodedata.category(char)]
    return f"U+{ord(char):04X} {name} ({kind})" if name else f"U+{ord(char):04X} ({kind})"


def problems(root: Path, names: Iterable[str]) -> list[str]:
    """``file:line:column: character`` for each forbidden character in the named files."""
    found = []
    for name in names:
        path = root / name
        if "node_modules" in Path(name).parts or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            found.append(f"{name}: not valid UTF-8 (byte {error.start})")
            continue
        found += [
            f"{name}:{line}:{column}: {describe(char)}"
            for line, column, char in hidden_characters(text)
        ]
    return found


def repository_files(root: Path) -> list[str]:
    """The files git tracks and the new ones it does not ignore, relative to ``root``."""
    assert GIT is not None
    done = subprocess.run(
        [GIT, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return sorted({name.decode("utf-8") for name in done.stdout.split(b"\0") if name})


@needs_a_checkout
def test_no_file_of_the_repository_holds_an_invisible_or_a_control_character() -> None:
    found = problems(PROJECT_ROOT, repository_files(PROJECT_ROOT))
    if found:
        report = ["Characters that cannot be seen:", *found, "", *HINT]
        pytest.fail("\n".join(report), pytrace=False)


@needs_a_checkout
def test_the_scan_reaches_code_configuration_and_files_without_an_extension() -> None:
    names = set(repository_files(PROJECT_ROOT))
    assert {"app/__init__.py", "pyproject.toml", "Dockerfile", "LICENSE"} <= names
    assert "tests/test_source_characters.py" in names


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_git_lists_the_tracked_and_the_new_files_not_the_ignored_ones_nor_a_nested_checkout(
    tmp_path: Path,
) -> None:
    """The nested checkout is how .claude/worktrees looks from the main checkout: git names its
    folder and does not descend, so the scan neither reads another copy of the repository nor the
    installed packages of its .venv."""

    def git(*args: str, cwd: Path = tmp_path) -> None:
        assert GIT is not None
        subprocess.run([GIT, *args], cwd=cwd, check=True, capture_output=True)

    nested = tmp_path / "worktrees" / "other"
    nested.mkdir(parents=True)
    (tmp_path / ".venv").mkdir()
    for name in (".gitignore", "tracked.py", "new.py", ".venv/ignored.py", "worktrees/other/in.py"):
        (tmp_path / name).write_text(".venv/\n" if name == ".gitignore" else "x = 1\n")
    git("init", "-q")
    git("init", "-q", cwd=nested)
    git("add", ".gitignore", "tracked.py")

    names = repository_files(tmp_path)

    assert names == [".gitignore", "new.py", "tracked.py", "worktrees/other/"]
    assert problems(tmp_path, names) == []


HIDDEN = [
    ("\N{ZERO WIDTH NO-BREAK SPACE}", "U+FEFF ZERO WIDTH NO-BREAK SPACE (format)"),
    ("\N{ZERO WIDTH SPACE}", "U+200B ZERO WIDTH SPACE (format)"),
    ("\N{RIGHT-TO-LEFT OVERRIDE}", "U+202E RIGHT-TO-LEFT OVERRIDE (format)"),
    ("\N{RIGHT-TO-LEFT ISOLATE}", "U+2067 RIGHT-TO-LEFT ISOLATE (format)"),
    ("\N{WORD JOINER}", "U+2060 WORD JOINER (format)"),
    ("\N{SOFT HYPHEN}", "U+00AD SOFT HYPHEN (format)"),
    ("\N{TAG LATIN CAPITAL LETTER A}", "U+E0041 TAG LATIN CAPITAL LETTER A (format)"),
    ("\x00", "U+0000 (control)"),
    ("\x07", "U+0007 (control)"),
    ("\x1b", "U+001B (control)"),
    ("\x7f", "U+007F (control)"),
    (chr(0x85), "U+0085 (control)"),
    (chr(0xE000), "U+E000 (private use)"),
    (chr(0xD800), "U+D800 (surrogate)"),
]


@pytest.mark.parametrize(("char", "label"), HIDDEN, ids=[label for _, label in HIDDEN])
def test_each_kind_of_hidden_character_is_found_where_it_stands_and_named(
    char: str, label: str
) -> None:
    text = "first\r\nsecond\n  x" + char + "\n"
    assert list(hidden_characters(text)) == [(3, 4, char)]
    assert describe(char) == label


def test_what_is_written_in_the_languages_of_the_documents_is_not_hidden() -> None:
    fine = [
        "ASCII with a tab\t, a line feed\n and a carriage return\r\n",
        "caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{EM DASH} \N{RIGHTWARDS ARROW} "
        "\N{LEFT DOUBLE QUOTATION MARK}",
        "\N{CJK UNIFIED IDEOGRAPH-65E5}\N{CJK UNIFIED IDEOGRAPH-672C}",
        "\N{WARNING SIGN}\N{VARIATION SELECTOR-16}",  # a selector is a mark, not a format character
        "\N{ARABIC LETTER MEEM}\N{ZERO WIDTH NON-JOINER}\N{ARABIC LETTER KHAH}",  # Persian
        "\N{MAN}\N{ZERO WIDTH JOINER}\N{WOMAN}",  # an emoji sequence
    ]
    assert [list(hidden_characters(text)) for text in fine] == [[] for _ in fine]


def test_a_file_is_read_as_text_whatever_its_name_and_skipped_when_it_is_not(
    tmp_path: Path,
) -> None:
    zero_width_space = "\N{ZERO WIDTH SPACE}"
    byte_order_mark = "\N{ZERO WIDTH NO-BREAK SPACE}"
    files = {
        "clean.py": b"x = 1\n",
        "bad.py": f"x = 1\n    y = '{zero_width_space}'\n".encode(),
        "Dockerfile": f"{byte_order_mark}FROM scratch\r\n".encode(),  # no extension, CRLF
        "font.woff2": b"wOF2\0\0" + zero_width_space.encode() + b"\xff\xfe",  # binary: a NUL
        "node_modules/pkg/index.js": f"x = '{zero_width_space}'\n".encode(),
        "latin1.txt": b"caf\xe9\n",
    }
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)

    found = problems(tmp_path, [*files, "deleted.py"])

    assert found == [
        "bad.py:2:10: U+200B ZERO WIDTH SPACE (format)",
        "Dockerfile:1:1: U+FEFF ZERO WIDTH NO-BREAK SPACE (format)",
        "latin1.txt: not valid UTF-8 (byte 3)",
    ]
