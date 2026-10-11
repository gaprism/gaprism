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

from app.service import blocklists as blocklists_service
from tests.exploit_helpers import epss_gz, kev_json, small_files  # noqa: F401
from tests.geo_helpers import gzipped, install_databases
from tests.test_blocklists import FEODO, PHISHING_ADDRESSES, PHISHING_DOMAINS, URLHAUS

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
    assert "kev: not installed" in result.output and "epss: not installed" in result.output
    for key in ("phishing", "feodo"):  # the lists that are on by default
        assert f"{key}: not installed" in result.output
    assert "Run `flask datasets update`" in result.output
    assert "IP geolocation by DB-IP.com (CC BY 4.0), https://db-ip.com" in result.output
    assert "Known Exploited Vulnerabilities Catalog, CISA" in result.output
    assert "Exploit Prediction Scoring System (EPSS), FIRST.Org, Inc." in result.output
    assert "Feodo Tracker, abuse.ch" in result.output
    assert "Phishing.Database (https://github.com/Phishing-Database/Phishing.Database" in (
        result.output
    )


def test_urlhaus_is_off_by_default_and_the_status_says_why(
    cli_runner: FlaskCliRunner, datasets_dir: Path
) -> None:
    """Its terms need the operator's decision, so the list is neither used nor credited."""
    status = cli_runner.invoke(args=["datasets", "status"]).output
    assert "urlhaus: switched off (BLOCKLIST_PROVIDERS)" in status
    assert "not on by default" in status and "may need a paid licence" in status
    assert "urlhaus: not installed" not in status  # it is not expected to be there
    assert "URLhaus, abuse.ch" not in status.split("Data:")[1]  # not credited: not used
    assert "phishing: switched off" not in status and "feodo: switched off" not in status


def test_status_shows_build_age_and_staleness(
    cli_runner: FlaskCliRunner, datasets_dir: Path
) -> None:
    install_databases(datasets_dir, built=TODAY - datetime.timedelta(days=60))
    result = cli_runner.invoke(args=["datasets", "status"])
    assert result.exit_code == 0, result.output
    assert "60 days old - STALE" in result.output
    assert "source: unknown" in result.output  # installed by hand: no manifest entry


@pytest.mark.usefixtures("small_files")
def test_update_installs_the_data_and_a_second_run_finds_it_current(
    app: Flask,
    cli_runner: FlaskCliRunner,
    datasets_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "BLOCKLIST_PROVIDERS", [])  # (they have tests of their own)
    source = install_databases(tmp_path / "source", built=TODAY)
    payloads = {
        "city": gzipped(source / "dbip-city-lite.mmdb"),
        "asn": gzipped(source / "dbip-asn-lite.mmdb"),
        "kev": kev_json(TODAY),
        "epss": epss_gz(tmp_path / "epss.csv.gz", TODAY).read_bytes(),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "known_exploited" in url:
            kind = "kev"
        elif "epss_scores" in url:
            kind = "epss"
        else:
            kind = "city" if "city" in url else "asn"
        return httpx.Response(200, content=payloads[kind])

    requested = serve(monkeypatch, handler)
    first = cli_runner.invoke(args=["datasets", "update"])
    assert first.exit_code == 0, first.output
    for kind in ("city", "asn", "kev", "epss"):
        assert f"{kind}: updated" in first.output
    assert (datasets_dir / "dbip-city-lite.mmdb").exists() and (datasets_dir / "kev.json").exists()
    assert (datasets_dir / "epss.sqlite").exists() and (datasets_dir / "datasets.json").exists()
    assert len(requested) == 4

    second = cli_runner.invoke(args=["datasets", "update"])
    assert second.exit_code == 0, second.output
    assert second.output.count("already current") == 4 and len(requested) == 4  # nothing fetched

    forced = cli_runner.invoke(args=["datasets", "update", "--force"])
    assert forced.output.count("updated") == 4 and len(requested) == 8

    status = cli_runner.invoke(args=["datasets", "status"]).output
    assert f"kev: as of {TODAY.isoformat()}" in status
    assert f"epss: as of {TODAY.isoformat()}" in status


def test_a_failed_download_is_reported_and_the_exit_code_says_so(
    cli_runner: FlaskCliRunner, datasets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    serve(monkeypatch, lambda request: httpx.Response(503))
    result = cli_runner.invoke(args=["datasets", "update"])
    assert result.exit_code == 1
    assert "city: FAILED" in result.output and "http_503" in result.output
    assert "kev: FAILED" in result.output and "epss: FAILED" in result.output
    for key in ("phishing", "feodo"):
        assert f"{key}: FAILED" in result.output
    assert "urlhaus" not in result.output.lower()  # off by default: not even asked for
    assert "At least one database could not be installed." in result.output


def served_blocklists(request: httpx.Request) -> httpx.Response:
    """The sample files of the three providers, by URL."""
    files = {
        "urlhaus.abuse.ch": URLHAUS,
        "feodotracker.abuse.ch": FEODO,
    }
    url = str(request.url)
    if request.url.host == "raw.githubusercontent.com":
        return httpx.Response(200, text=PHISHING_ADDRESSES if "IPs" in url else PHISHING_DOMAINS)
    return httpx.Response(200, text=files[request.url.host])


def small_blocklists(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sample files are far smaller than the real lists, which the update refuses."""
    real = blocklists_service.update
    monkeypatch.setattr(
        blocklists_service, "update", lambda *args, **kwargs: real(*args, relaxed=True, **kwargs)
    )


def test_update_installs_only_the_blocklists_the_owner_chose(
    app: Flask,
    cli_runner: FlaskCliRunner,
    datasets_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "BLOCKLIST_PROVIDERS", ["feodo", "urlhaus"])
    small_blocklists(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host in ("urlhaus.abuse.ch", "feodotracker.abuse.ch"):
            return served_blocklists(request)
        return httpx.Response(503)  # the other data does not matter here

    requested = serve(monkeypatch, handler)
    result = cli_runner.invoke(args=["datasets", "update"])
    assert "urlhaus: updated, as of" in result.output and "feodo: updated, as of" in result.output
    assert "phishing" not in result.output.split("Data:")[0]  # not downloaded, not even named
    assert not any("githubusercontent" in url for url in requested)
    assert (datasets_dir / "urlhaus.sqlite").exists() and (datasets_dir / "feodo.sqlite").exists()
    assert not (datasets_dir / "phishing.sqlite").exists()
    credits = result.output.split("Data:")[1]
    assert "URLhaus, abuse.ch" in credits and "Phishing.Database" not in credits

    status = cli_runner.invoke(args=["datasets", "status"]).output
    assert f"urlhaus: as of {TODAY.isoformat()}" in status and "feodo: as of" in status
    assert "phishing: switched off (BLOCKLIST_PROVIDERS)" in status
    again = cli_runner.invoke(args=["datasets", "update"]).output
    assert "urlhaus: already current" in again and "feodo: already current" in again


def test_with_the_blocklists_switched_off_nothing_of_them_is_downloaded_or_credited(
    app: Flask,
    cli_runner: FlaskCliRunner,
    datasets_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "BLOCKLIST_PROVIDERS", [])
    requested = serve(monkeypatch, lambda request: httpx.Response(503))
    result = cli_runner.invoke(args=["datasets", "update"])
    hosts = {url.split("/")[2] for url in requested}
    assert not hosts & {"urlhaus.abuse.ch", "feodotracker.abuse.ch", "raw.githubusercontent.com"}
    assert "urlhaus" not in result.output.lower() and "phishing" not in result.output.lower()
    status = cli_runner.invoke(args=["datasets", "status"]).output
    for key in ("urlhaus", "phishing", "feodo"):
        assert f"{key}: switched off (BLOCKLIST_PROVIDERS)" in status
    assert "abuse.ch" not in status.split("Data:")[1]  # no credit for lists that are not used
