"""`flask datasets status` and `flask datasets update` (downloads are scripted, no network)."""

from __future__ import annotations

import datetime
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from flask import Flask
from flask.testing import FlaskCliRunner

from tests.geo_helpers import gzipped, install_databases

TODAY = datetime.datetime.now(datetime.UTC).date()
REAL_CLIENT = httpx.Client


@pytest.fixture
def datasets_dir(app: Flask, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "datasets"
    monkeypatch.setitem(app.config, "DATASETS_DIR", str(directory))
    return directory


def serve(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> list[str]:
    """Make the command's HTTP client talk to ``handler``; returns the requested URLs."""
    requested: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return handler(request)

    def client(**options: Any) -> httpx.Client:
        return REAL_CLIENT(transport=httpx.MockTransport(record), follow_redirects=True)

    monkeypatch.setattr("app.commands.httpx.Client", client)
    return requested


def test_status_says_what_is_missing_and_how_to_fix_it(
    cli_runner: FlaskCliRunner, datasets_dir: Path
) -> None:
    result = cli_runner.invoke(args=["datasets", "status"])
    assert result.exit_code == 0, result.output
    assert f"Directory: {datasets_dir}" in result.output
    assert "city: not installed" in result.output and "asn: not installed" in result.output
    assert "Run `flask datasets update`" in result.output
    assert "IP geolocation by DB-IP.com (CC BY 4.0), https://db-ip.com" in result.output


def test_status_shows_build_age_and_staleness(
    cli_runner: FlaskCliRunner, datasets_dir: Path
) -> None:
    install_databases(datasets_dir, built=TODAY - datetime.timedelta(days=60))
    result = cli_runner.invoke(args=["datasets", "status"])
    assert result.exit_code == 0, result.output
    assert "60 days old - STALE" in result.output
    assert "source: unknown" in result.output  # installed by hand: no manifest entry


def test_update_installs_the_databases_and_a_second_run_finds_them_current(
    cli_runner: FlaskCliRunner,
    datasets_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = install_databases(tmp_path / "source", built=TODAY)
    payloads = {
        "city": gzipped(source / "dbip-city-lite.mmdb"),
        "asn": gzipped(source / "dbip-asn-lite.mmdb"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        kind = "city" if "city" in str(request.url) else "asn"
        return httpx.Response(200, content=payloads[kind])

    requested = serve(monkeypatch, handler)
    first = cli_runner.invoke(args=["datasets", "update"])
    assert first.exit_code == 0, first.output
    assert "city: updated" in first.output and "asn: updated" in first.output
    assert (datasets_dir / "dbip-city-lite.mmdb").exists() and (
        datasets_dir / "datasets.json"
    ).exists()
    assert len(requested) == 2

    second = cli_runner.invoke(args=["datasets", "update"])
    assert second.exit_code == 0, second.output
    assert second.output.count("already current") == 2 and len(requested) == 2  # nothing fetched

    forced = cli_runner.invoke(args=["datasets", "update", "--force"])
    assert forced.output.count("updated") == 2 and len(requested) == 4


def test_a_failed_download_is_reported_and_the_exit_code_says_so(
    cli_runner: FlaskCliRunner, datasets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    serve(monkeypatch, lambda request: httpx.Response(503))
    result = cli_runner.invoke(args=["datasets", "update"])
    assert result.exit_code == 1
    assert "city: FAILED" in result.output and "http_503" in result.output
    assert "At least one database could not be installed." in result.output
