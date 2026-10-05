"""docs/rules.md is generated from the rules; it must say what the code says."""

from __future__ import annotations

import re

from app.rules import RULES
from app.rules.docs import DOC_PATH, main, render


def test_the_committed_document_is_current() -> None:
    assert DOC_PATH.read_text(encoding="utf-8") == render(), (
        "docs/rules.md is out of date: run `uv run python -m app.rules.docs`"
    )


def test_every_rule_is_documented_once_with_its_index_row() -> None:
    text = render()
    headings = re.findall(r"^### `([A-Z0-9_]+)`$", text, flags=re.MULTILINE)
    assert sorted(headings) == sorted(RULES)
    assert len(headings) == len(set(headings))
    for rule_id in RULES:
        assert f"| [`{rule_id}`](#{rule_id.lower()}) |" in text


def test_a_rule_reads_as_a_sentence_not_as_a_template() -> None:
    text = render()
    assert "%(" not in text.split("## Host rules", 1)[1]  # placeholders appear as {name}
    assert "*Says:* The TLS certificate of {host} is not valid for clients: {failures}." in text
    assert "**Certificate not valid** · High or Medium · reads the `tls` check · version 1" in text
    assert "## Host rules" in text and "## Address rules" in text and "## Domain rules" in text


def test_the_document_names_the_owner_specified_rules_and_their_settings() -> None:
    text = render()
    assert "`LOCATION_OUTSIDE_EU_CH`" in text and "`DATA_LOCATION_ALLOWED`" in text
    assert "`PUBLIC_BREACH_HISTORY`" in text and "`BREACH_RECENT_MONTHS`" in text
    assert "No finding is not a clean bill of health" in text


def test_the_command_reports_whether_the_file_is_current(capsys: object) -> None:
    assert main(["--check"]) == 0
