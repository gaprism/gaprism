"""docs/export-format.md names exactly the keys and columns the exports have."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.service import export as export_service
from app.service.export import FINDING_COLUMNS, HOST_COLUMNS
from tests.test_findings_service import RULES_CONFIG
from tests.test_summary import evaluated

DOC = (Path(__file__).resolve().parents[1] / "docs" / "export-format.md").read_text(
    encoding="utf-8"
)


def section(heading: str) -> str:
    """The text under a heading, up to the next heading."""
    start = DOC.index(f"\n{heading}\n") + len(heading) + 2
    end = re.search(r"^#{1,3} ", DOC[start:], re.MULTILINE)
    return DOC[start : start + end.start()] if end else DOC[start:]


def table_keys(block: str) -> list[str]:
    return re.findall(r"^\| `([a-z_]+)` \|", block, re.MULTILINE)


def record_keys(label: str) -> list[str]:
    """The keys named in prose like ``A **check** is `{id, check, status}` ``."""
    found = re.search(rf"A \*\*{label}\*\* is `\{{([^}}]+)\}}`", DOC)
    assert found, label
    return [key.strip() for key in found.group(1).split(",")]


def test_the_csv_columns_are_documented_in_order() -> None:
    assert table_keys(section("### Hosts: one row per reviewed host")) == list(HOST_COLUMNS)
    assert table_keys(section("### Findings: one row per finding")) == list(FINDING_COLUMNS)


def test_the_json_keys_are_documented(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    now = datetime(2026, 10, 5, 12, 30, tzinfo=UTC)
    data = export_service.build_export(db_session, scan.assessment, scan, RULES_CONFIG, now=now)
    document = export_service.to_dict(data)

    assert table_keys(section("## JSON")) == list(document)
    assert record_keys("check") == list(document["hosts"][0]["checks"][0])
    assert record_keys("finding") == list(document["findings"][0])
    host = {key for key in document["hosts"][0] if key != "checks"}
    for key in host:  # every key of a host is named in the table row for ``hosts``
        assert f"`{key}`" in section("## JSON")
