"""Installing the DB-IP Lite databases: sources, fallbacks, validation, atomicity (no network)."""

from __future__ import annotations

import datetime
import gzip
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.service.geo import DbIpProvider, dataset_status, update_datasets
from app.service.geo import datasets as datasets_module
from app.service.geo.datasets import SPECS, candidate_urls
from tests.geo_helpers import (
    ASN_RECORDS,
    ASN_TYPE,
    CITY_RECORDS,
    CITY_TYPE,
    gzipped,
    install_databases,
    place,
    write_mmdb,
)

TODAY = datetime.date(2026, 10, 15)
OFFICIAL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
CITY_NOW = OFFICIAL.format(kind="city", month="2026-10")
CITY_PREVIOUS = OFFICIAL.format(kind="city", month="2026-09")
ASN_NOW = OFFICIAL.format(kind="asn", month="2026-10")
ASN_PREVIOUS = OFFICIAL.format(kind="asn", month="2026-09")
MIRROR = "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz"
IPV4_ONLY = {cidr: record for cidr, record in CITY_RECORDS.items() if ":" not in cidr}

Reply = httpx.Response | Exception


class Server:
    """Scripted download servers; unknown URLs are 404. Records every request."""

    def __init__(self, routes: dict[str, Reply]) -> None:
        self.routes = routes
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        reply = self.routes.get(str(request.url), httpx.Response(404))
        if isinstance(reply, Exception):
            raise reply
        return reply

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self), follow_redirects=True)


@pytest.fixture
def files(tmp_path: Path) -> dict[str, bytes]:
    """Valid gzip-compressed databases, built on the test's "today"."""
    source = install_databases(tmp_path / "source", built=TODAY)
    return {
        "city": gzipped(source / "dbip-city-lite.mmdb"),
        "asn": gzipped(source / "dbip-asn-lite.mmdb"),
    }


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    return tmp_path / "datasets"


def ok(content: bytes) -> httpx.Response:
    return httpx.Response(200, content=content)


def leftovers(directory: Path) -> list[str]:
    """Temporary files an update must never leave behind."""
    return sorted(path.name for path in directory.iterdir() if path.name.endswith(".tmp"))


# ------------------------------------------------------------------------------ the happy path


def test_update_installs_both_databases_and_records_what_was_installed(
    directory: Path, files: dict[str, bytes], tmp_path: Path
) -> None:
    server = Server({CITY_NOW: ok(files["city"]), ASN_NOW: ok(files["asn"])})
    reports = update_datasets(directory, server.client(), today=TODAY)

    assert [(r.kind, r.status, r.source) for r in reports] == [
        ("city", "updated", CITY_NOW),
        ("asn", "updated", ASN_NOW),
    ]
    assert DbIpProvider(directory).lookup("8.8.8.8").country == "US"

    manifest = json.loads((directory / "datasets.json").read_text(encoding="utf-8"))
    installed = (tmp_path / "source" / "dbip-city-lite.mmdb").read_bytes()
    assert manifest["city"]["source"] == CITY_NOW
    assert manifest["city"]["sha256"] == hashlib.sha256(installed).hexdigest()
    assert manifest["city"]["size"] == len(installed) == reports[0].size
    assert (manifest["city"]["database_type"], manifest["city"]["build"]) == (
        CITY_TYPE,
        "2026-10-15",
    )
    assert leftovers(directory) == []

    city, asn = dataset_status(directory, today=TODAY)
    assert (city.present, city.build, city.age_days, city.stale) == (True, "2026-10-15", 0, False)
    assert asn.source == ASN_NOW and asn.sha256 == manifest["asn"]["sha256"]


def test_a_redirect_to_the_file_is_followed(directory: Path, files: dict[str, bytes]) -> None:
    real = "https://files.example.net/city.mmdb.gz"
    server = Server(
        {
            CITY_NOW: httpx.Response(302, headers={"Location": real}),
            real: ok(files["city"]),
        }
    )
    reports = update_datasets(directory, server.client(), today=TODAY, kinds=["city"])
    assert [(r.kind, r.status) for r in reports] == [("city", "updated")]


# ----------------------------------------------------------------------------- sources, fallbacks


def test_the_previous_month_is_used_when_the_new_one_is_not_published_yet(
    directory: Path, files: dict[str, bytes]
) -> None:
    server = Server({CITY_PREVIOUS: ok(files["city"]), ASN_PREVIOUS: ok(files["asn"])})
    reports = update_datasets(directory, server.client(), today=TODAY)
    assert [r.source for r in reports] == [CITY_PREVIOUS, ASN_PREVIOUS]
    assert server.requests == [CITY_NOW, CITY_PREVIOUS, ASN_NOW, ASN_PREVIOUS]


def test_the_city_mirror_is_the_last_resort_and_a_failure_names_every_attempt(
    directory: Path, files: dict[str, bytes]
) -> None:
    server = Server({MIRROR: ok(files["city"])})
    city, asn = update_datasets(directory, server.client(), today=TODAY)

    assert (city.status, city.source) == ("updated", MIRROR)
    assert asn.status == "failed" and asn.source is None  # no mirror for the ASN database
    assert asn.detail == "download.db-ip.com: http_404; download.db-ip.com: http_404"
    assert (directory / "dbip-city-lite.mmdb").exists()
    assert not (directory / "dbip-asn-lite.mmdb").exists()


def test_the_mirror_is_validated_like_any_other_source(directory: Path) -> None:
    html = httpx.Response(200, content=b"<html>rate limited</html>")
    city = update_datasets(directory, Server({MIRROR: html}).client(), today=TODAY, kinds=["city"])
    assert city[0].status == "failed" and "cdn.jsdelivr.net: not_gzip" in city[0].detail


def test_network_problems_are_reported_with_stable_codes(directory: Path) -> None:
    server = Server(
        {
            CITY_NOW: httpx.ConnectError("refused"),
            CITY_PREVIOUS: httpx.ReadTimeout("slow"),
            MIRROR: httpx.Response(503),
        }
    )
    city = update_datasets(directory, server.client(), today=TODAY, kinds=["city"])[0]
    assert city.status == "failed"
    assert city.detail == (
        "download.db-ip.com: connection_failed; download.db-ip.com: timeout; "
        "cdn.jsdelivr.net: http_503"
    )


# ------------------------------------------------------------------------------ validation


def _database(directory: Path, name: str, kind: str, records: Any, **options: Any) -> bytes:
    path = write_mmdb(directory / name, kind, records, **options)
    return gzipped(path)


def _bad_downloads(tmp_path: Path) -> dict[str, tuple[bytes, str]]:
    src = tmp_path / "bad"
    return {
        "html page": (b"<html>Not found</html>", "not_gzip"),
        "gzip of nothing useful": (gzip.compress(b"hello, not a database"), "not_a_database"),
        "the wrong kind of database": (
            _database(src, "asn.mmdb", ASN_TYPE, ASN_RECORDS, built=TODAY),
            "wrong_database_type",
        ),
        "an IPv4-only database": (
            _database(src, "v4.mmdb", CITY_TYPE, IPV4_ONLY, built=TODAY, ip_version=4),
            "not_ipv6",
        ),
        "an old build": (
            _database(
                src, "old.mmdb", CITY_TYPE, CITY_RECORDS, built=TODAY - datetime.timedelta(days=200)
            ),
            "too_old",
        ),
        "a build from the future": (
            _database(
                src,
                "future.mmdb",
                CITY_TYPE,
                CITY_RECORDS,
                built=TODAY + datetime.timedelta(days=30),
            ),
            "build_date_in_the_future",
        ),
        "a database that does not answer the probe": (
            _database(
                src, "empty.mmdb", CITY_TYPE, {"1.1.1.0/24": place("AU", "Australia")}, built=TODAY
            ),
            "probe_failed",
        ),
    }


def test_a_download_that_is_not_the_expected_database_is_refused(
    directory: Path, tmp_path: Path
) -> None:
    for label, (content, reason) in _bad_downloads(tmp_path).items():
        report = update_datasets(
            directory / label.replace(" ", "-"),
            Server({CITY_NOW: ok(content)}).client(),
            today=TODAY,
            kinds=["city"],
        )[0]
        assert report.status == "failed", label
        assert f"download.db-ip.com: {reason}" in report.detail, label
        assert not (directory / label.replace(" ", "-") / "dbip-city-lite.mmdb").exists(), label


def test_a_truncated_download_is_refused(directory: Path, files: dict[str, bytes]) -> None:
    cut = files["city"][: len(files["city"]) // 2]
    report = update_datasets(
        directory, Server({CITY_NOW: ok(cut)}).client(), today=TODAY, kinds=["city"]
    )[0]
    assert "incomplete_download" in report.detail


def test_a_gzip_bomb_is_stopped_by_the_size_limit(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(datasets_module, "MAX_DATABASE_BYTES", 10_000)
    bomb = gzip.compress(b"\0" * 5_000_000)  # a few KB that expand to 5 MB
    assert len(bomb) < 10_000
    report = update_datasets(
        directory, Server({CITY_NOW: ok(bomb)}).client(), today=TODAY, kinds=["city"]
    )[0]
    assert "database_too_large" in report.detail
    assert leftovers(directory) == [] and not (directory / "dbip-city-lite.mmdb").exists()


def test_an_oversized_download_is_stopped_whether_or_not_it_announces_its_size(
    directory: Path, files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(datasets_module, "MAX_DOWNLOAD_BYTES", 100)

    def stream() -> Iterator[bytes]:  # no Content-Length: only the running count can catch it
        yield from (files["city"][i : i + 50] for i in range(0, len(files["city"]), 50))

    announced = ok(files["city"])
    unannounced = httpx.Response(200, content=stream())
    for response in (announced, unannounced):
        report = update_datasets(
            directory, Server({CITY_NOW: response}).client(), today=TODAY, kinds=["city"]
        )[0]
        assert "download_too_large" in report.detail
    assert leftovers(directory) == []


# ---------------------------------------------------------------------------- atomic, idempotent


def test_a_failed_update_leaves_the_working_installation_untouched(
    directory: Path, files: dict[str, bytes]
) -> None:
    install_databases(directory, built=TODAY - datetime.timedelta(days=40))
    before = {p.name: p.read_bytes() for p in directory.iterdir()}

    reports = update_datasets(directory, Server({}).client(), today=TODAY)  # everything is 404

    assert [r.status for r in reports] == ["failed", "failed"]
    assert {p.name: p.read_bytes() for p in directory.iterdir() if p.suffix != ".json"} == before
    assert DbIpProvider(directory).lookup("85.1.1.1").country == "CH"  # still serving
    assert leftovers(directory) == []


def test_a_bad_replacement_does_not_replace_a_good_file(directory: Path, tmp_path: Path) -> None:
    install_databases(directory, built=TODAY - datetime.timedelta(days=40))
    good = (directory / "dbip-city-lite.mmdb").read_bytes()
    bad = _bad_downloads(tmp_path)["the wrong kind of database"][0]
    update_datasets(directory, Server({CITY_NOW: ok(bad)}).client(), today=TODAY, kinds=["city"])
    assert (directory / "dbip-city-lite.mmdb").read_bytes() == good


def test_this_months_build_is_not_downloaded_again_unless_forced(
    directory: Path, files: dict[str, bytes]
) -> None:
    server = Server({CITY_NOW: ok(files["city"]), ASN_NOW: ok(files["asn"])})
    update_datasets(directory, server.client(), today=TODAY)
    server.requests.clear()

    again = update_datasets(directory, server.client(), today=TODAY)
    assert [(r.status, r.detail) for r in again] == [
        ("current", "build 2026-10-15"),
        ("current", "build 2026-10-15"),
    ]
    assert server.requests == []  # nothing was fetched

    forced = update_datasets(directory, server.client(), today=TODAY, force=True)
    assert [r.status for r in forced] == ["updated", "updated"]
    assert len(server.requests) == 2


def test_updating_one_dataset_keeps_the_record_of_the_other(
    directory: Path, files: dict[str, bytes]
) -> None:
    update_datasets(
        directory,
        Server({CITY_NOW: ok(files["city"]), ASN_NOW: ok(files["asn"])}).client(),
        today=TODAY,
    )
    update_datasets(
        directory,
        Server({ASN_NOW: ok(files["asn"])}).client(),
        today=TODAY,
        force=True,
        kinds=["asn"],
    )
    manifest = json.loads((directory / "datasets.json").read_text(encoding="utf-8"))
    assert sorted(manifest) == ["asn", "city"]


# ------------------------------------------------------------------------------ status


def test_status_says_what_is_missing_stale_or_broken(directory: Path) -> None:
    city, asn = dataset_status(directory, today=TODAY)
    assert (city.present, city.problem, asn.problem) == (False, "not installed", "not installed")

    install_databases(directory, built=TODAY - datetime.timedelta(days=60))
    (directory / "dbip-asn-lite.mmdb").write_bytes(b"garbage")
    city, asn = dataset_status(directory, today=TODAY)
    assert (city.present, city.age_days, city.stale) == (True, 60, True)
    assert (asn.present, asn.problem) == (False, "unreadable")


def test_candidate_urls_roll_over_the_new_year() -> None:
    city = next(spec for spec in SPECS if spec.kind == "city")
    urls = candidate_urls(city, datetime.date(2026, 1, 3))
    assert urls[0].endswith("dbip-city-lite-2026-01.mmdb.gz")
    assert urls[1].endswith("dbip-city-lite-2025-12.mmdb.gz")
    assert urls[2] == MIRROR
