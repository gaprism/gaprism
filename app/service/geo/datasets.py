"""Downloading, validating and installing the DB-IP Lite databases (``flask datasets update``).

DB-IP publishes free monthly files (CC BY 4.0, attribution required) as gzip-compressed MMDB
files. A download is accepted only if it is complete, bounded, a database of the expected kind,
recent, and answers a probe lookup; it replaces the installed file atomically, so a failed update
never damages a working installation. Source and SHA-256 of what was installed are recorded in
``datasets.json`` next to the files.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import tempfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import maxminddb
from maxminddb.errors import InvalidDatabaseError

from app.service.geo.models import DatabaseInfo
from app.service.geo.provider import ASN_FILE, CITY_FILE

MANIFEST = "datasets.json"
ATTRIBUTION = "IP geolocation by DB-IP.com"
ATTRIBUTION_URL = "https://db-ip.com"
LICENCE = "CC BY 4.0"

MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024  # the compressed city file is about 60 MB
MAX_DATABASE_BYTES = 600 * 1024 * 1024  # decompressed (about 127 MB): a gzip bomb stops here
MAX_AGE_DAYS = 120  # a database built longer ago than this is refused
STALE_AFTER_DAYS = 45  # installed databases older than this are flagged
CHUNK = 1024 * 1024
PROBE_IP = "8.8.8.8"  # present in every real DB-IP database


class DatasetError(Exception):
    """A download or a downloaded file was rejected; ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DatasetSpec:
    kind: str
    filename: str
    type_prefix: str  # what ``database_type`` must start with
    official: str  # {year:04d} and {month:02d} are filled in
    mirrors: tuple[str, ...]
    probe: Callable[[object], bool]  # does the record for PROBE_IP have the expected shape?


def _city_probe(record: object) -> bool:
    country = record.get("country") if isinstance(record, Mapping) else None
    return isinstance(country, Mapping) and isinstance(country.get("iso_code"), str)


def _asn_probe(record: object) -> bool:
    return isinstance(record, Mapping) and isinstance(record.get("autonomous_system_number"), int)


SPECS = (
    DatasetSpec(
        "city",
        CITY_FILE,
        "DBIP-City",
        "https://download.db-ip.com/free/dbip-city-lite-{year:04d}-{month:02d}.mmdb.gz",
        # The same file, re-published monthly by wp-statistics (a third party: validated).
        ("https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz",),
        _city_probe,
    ),
    DatasetSpec(
        "asn",
        ASN_FILE,
        "DBIP-ASN",
        "https://download.db-ip.com/free/dbip-asn-lite-{year:04d}-{month:02d}.mmdb.gz",
        (),
        _asn_probe,
    ),
)


@dataclass(frozen=True)
class UpdateReport:
    kind: str
    status: str  # updated | current | failed
    detail: str
    source: str | None = None
    info: DatabaseInfo | None = None
    size: int | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class DatasetStatus:
    kind: str
    present: bool
    build: str | None
    age_days: int | None
    stale: bool
    source: str | None
    sha256: str | None
    problem: str | None


def _months(today: datetime.date) -> list[tuple[int, int]]:
    """This month, then the previous one (DB-IP publishes at the start of a month)."""
    previous = today.replace(day=1) - datetime.timedelta(days=1)
    return [(today.year, today.month), (previous.year, previous.month)]


def candidate_urls(spec: DatasetSpec, today: datetime.date) -> list[str]:
    official = [spec.official.format(year=year, month=month) for year, month in _months(today)]
    return [*official, *spec.mirrors]


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


# --------------------------------------------------------------------------- download


def _download(client: httpx.Client, url: str, target: Path) -> tuple[int, str]:
    """Stream ``url`` (a gzip file) into ``target`` decompressed; return (size, sha256).

    Both the download and the decompressed output are bounded, so neither a huge file nor a
    gzip bomb can fill the disk.
    """
    digest = hashlib.sha256()
    produced = received = 0
    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        # "identity": the file is already gzip; transfer compression on top would only add work.
        request_headers = {"Accept-Encoding": "identity"}
        with (
            client.stream("GET", url, headers=request_headers) as response,
            target.open("wb") as out,
        ):
            if response.status_code != 200:
                raise DatasetError(f"http_{response.status_code}")
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_DOWNLOAD_BYTES:
                raise DatasetError("download_too_large")
            for chunk in response.iter_bytes(CHUNK):
                received += len(chunk)
                if received > MAX_DOWNLOAD_BYTES:
                    raise DatasetError("download_too_large")
                pending = chunk
                while pending:
                    data = decompressor.decompress(pending, CHUNK)
                    pending = decompressor.unconsumed_tail
                    produced += len(data)
                    if produced > MAX_DATABASE_BYTES:
                        raise DatasetError("database_too_large")
                    digest.update(data)
                    out.write(data)
            tail = decompressor.flush()
            produced += len(tail)
            digest.update(tail)
            out.write(tail)
    except zlib.error as exc:
        raise DatasetError("not_gzip") from exc
    except httpx.TimeoutException as exc:
        raise DatasetError("timeout") from exc
    except httpx.HTTPError as exc:
        raise DatasetError("connection_failed") from exc
    if not decompressor.eof or produced == 0:
        raise DatasetError("incomplete_download")
    return produced, digest.hexdigest()


# --------------------------------------------------------------------------- validation


def validate_database(path: Path, spec: DatasetSpec, today: datetime.date) -> DatabaseInfo:
    """Accept ``path`` only if it is a recent database of the kind ``spec`` describes."""
    try:
        reader = maxminddb.open_database(str(path), mode=maxminddb.MODE_FILE)
    except (InvalidDatabaseError, ValueError, OSError) as exc:
        raise DatasetError("not_a_database") from exc
    with reader:
        meta = reader.metadata()
        if not str(meta.database_type).startswith(spec.type_prefix):
            raise DatasetError("wrong_database_type")
        if meta.ip_version != 6:
            raise DatasetError("not_ipv6")
        built = datetime.datetime.fromtimestamp(meta.build_epoch, datetime.UTC).date()
        if built > today + datetime.timedelta(days=2):
            raise DatasetError("build_date_in_the_future")
        if today - built > datetime.timedelta(days=MAX_AGE_DAYS):
            raise DatasetError("too_old")
        try:
            record = reader.get(PROBE_IP)
        except (InvalidDatabaseError, ValueError) as exc:
            raise DatasetError("probe_failed") from exc
        if not spec.probe(record):
            raise DatasetError("probe_failed")
    return DatabaseInfo(spec.kind, str(meta.database_type), built.isoformat())


def installed_info(path: Path, spec: DatasetSpec) -> DatabaseInfo | None:
    """The installed file's identity, ``None`` if there is none or it is unreadable."""
    if not path.is_file():
        return None
    try:
        with maxminddb.open_database(str(path), mode=maxminddb.MODE_FILE) as reader:
            meta = reader.metadata()
            built = datetime.datetime.fromtimestamp(meta.build_epoch, datetime.UTC).date()
            return DatabaseInfo(spec.kind, str(meta.database_type), built.isoformat())
    except (InvalidDatabaseError, ValueError, OSError):
        return None


# --------------------------------------------------------------------------- manifest


def read_manifest(directory: Path) -> dict[str, Any]:
    try:
        data = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_manifest(directory: Path, manifest: Mapping[str, Any]) -> None:
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=".manifest-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as out:
            json.dump(manifest, out, indent=2, sort_keys=True)
        os.replace(name, directory / MANIFEST)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- update


def _update_one(
    spec: DatasetSpec,
    directory: Path,
    client: httpx.Client,
    today: datetime.date,
    force: bool,
    manifest: dict[str, Any],
) -> UpdateReport:
    final = directory / spec.filename
    existing = installed_info(final, spec)
    if not force and existing is not None and existing.build[:7] == today.isoformat()[:7]:
        return UpdateReport(spec.kind, "current", f"build {existing.build}", info=existing)

    attempts: list[str] = []
    for url in candidate_urls(spec, today):
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{spec.kind}-", suffix=".tmp")
        os.close(descriptor)
        temporary = Path(name)
        try:
            size, sha256 = _download(client, url, temporary)
            info = validate_database(temporary, spec, today)
            os.replace(temporary, final)
        except DatasetError as exc:
            attempts.append(f"{_host(url)}: {exc.reason}")
            continue
        finally:
            temporary.unlink(missing_ok=True)
        manifest[spec.kind] = {
            "file": spec.filename,
            "source": url,
            "downloaded_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "sha256": sha256,
            "size": size,
            "database_type": info.database_type,
            "build": info.build,
        }
        return UpdateReport(spec.kind, "updated", f"build {info.build}", url, info, size, sha256)
    return UpdateReport(spec.kind, "failed", "; ".join(attempts) or "no source")


def update_datasets(
    directory: Path,
    client: httpx.Client,
    *,
    today: datetime.date | None = None,
    force: bool = False,
    kinds: Sequence[str] | None = None,
) -> list[UpdateReport]:
    """Bring the databases up to date; every dataset is tried even if another one failed."""
    today = today or datetime.datetime.now(datetime.UTC).date()
    directory.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(directory)
    reports = [
        _update_one(spec, directory, client, today, force, manifest)
        for spec in SPECS
        if not kinds or spec.kind in kinds
    ]
    write_manifest(directory, manifest)
    return reports


def dataset_status(directory: Path, *, today: datetime.date | None = None) -> list[DatasetStatus]:
    """What is installed, how old it is and where it came from."""
    today = today or datetime.datetime.now(datetime.UTC).date()
    manifest = read_manifest(directory)
    statuses = []
    for spec in SPECS:
        path = directory / spec.filename
        raw = manifest.get(spec.kind)
        entry: dict[str, Any] = raw if isinstance(raw, dict) else {}
        info = installed_info(path, spec)
        if info is None:
            problem = "unreadable" if path.exists() else "not installed"
            statuses.append(DatasetStatus(spec.kind, False, None, None, False, None, None, problem))
            continue
        age = (today - datetime.date.fromisoformat(info.build)).days
        statuses.append(
            DatasetStatus(
                spec.kind,
                True,
                info.build,
                age,
                age > STALE_AFTER_DAYS,
                entry.get("source"),
                entry.get("sha256"),
                None,
            )
        )
    return statuses
