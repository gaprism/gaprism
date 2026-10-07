"""Blocklists of hosts and addresses that serve malware or phishing, installed and read offline.

Three public providers, downloaded by ``flask datasets update`` (nothing about an assessment is
sent) and read from disk when a host is checked:

- **URLhaus host file** (abuse.ch): the host names of malware URLs that are active or were added in
  the last 48 hours. The provider leaves out the million most visited sites.
- **Phishing.Database** (domains and addresses): hosts and addresses of phishing pages that still
  answered when the project last tested them.
- **Feodo Tracker** (abuse.ch): addresses of botnet command-and-control servers that answer as one.

Each provider becomes a small SQLite file (``urlhaus.sqlite``, ``phishing.sqlite``,
``feodo.sqlite``) so that a lookup reads only the rows it asks for, and a provider that cannot be
updated leaves the others alone. A download is accepted only if it is complete, bounded, of the
expected shape and big enough to be the real list, and it replaces the installed file atomically.
Source and SHA-256 of what was installed go into ``datasets.json`` with the other data.

What a listing says, and what it does not: somebody reported or measured that the host served such
content, and the maintainers kept it; it does not say what is there today, and a name that is not
listed says nothing (the lists hold what their maintainers have seen). A shared address can be
listed because of a neighbour. Entries for the most visited sites are never kept, whatever a feed
says: a feed that lists them has been tampered with or is broken.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os
import re
import sqlite3
import tempfile
import threading
import time
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.service.geo.datasets import (
    DatasetError,
    DatasetStatus,
    UpdateReport,
    read_manifest,
    write_manifest,
)

MAX_DOWNLOAD = 96 * 1024 * 1024  # the biggest list is about 12 MB
MAX_LINE = 4096
MAX_ROWS = 3_000_000  # the biggest list has about 500,000
STALE_AFTER_DAYS = 3  # the lists change every few minutes to hours
REFRESH_AFTER = datetime.timedelta(hours=6)  # `update` leaves a download this young alone
RELOAD_CHECK_SECONDS = 30.0
LOOKUP_BATCH = 400
MAX_ADDRESSES = 8  # per host
CHUNK = 1024 * 1024

# Hosts that no feed may list: if one does, the entry is dropped, and a list with several of them
# is refused. (The most visited sites are not hosts of malware; a feed that says so is not to be
# believed.)
NEVER_LISTED = frozenset(
    f"{prefix}{name}"
    for name in (
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "github.com",
        "wikipedia.org",
        "cloudflare.com",
        "mozilla.org",
        "youtube.com",
        "facebook.com",
    )
    for prefix in ("", "www.")
)
MAX_IMPLAUSIBLE = 3

HOST = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_-]{2,63}")
UPDATED = re.compile(r"Last updated:\s*(\d{4}-\d{2}-\d{2})")
DECLARED_COUNT = re.compile(r"#\s*END\s+(\d+)\s+entries", re.IGNORECASE)


# --------------------------------------------------------------------------- what is listed


@dataclass(frozen=True)
class Source:
    """One downloaded file of a provider."""

    key: str  # "domains" | "addresses"
    url: str
    parser: str  # hostfile | domain_list | address_list
    minimum: int  # the fewest entries a real file has
    trailer: bool = False  # the file ends with "# END n entries": one without it was cut short


@dataclass(frozen=True)
class Provider:
    key: str
    name: str
    kind: str  # what its lists are about: malware | phishing | botnet
    filename: str
    sources: tuple[Source, ...]
    page: str  # where the provider describes itself and its terms
    licence: str
    attribution: str  # how the report and the CLI credit the data


PROVIDERS: dict[str, Provider] = {
    provider.key: provider
    for provider in (
        Provider(
            "urlhaus",
            "abuse.ch URLhaus",
            "malware",
            "urlhaus.sqlite",
            (Source("domains", "https://urlhaus.abuse.ch/downloads/hostfile/", "hostfile", 10),),
            "https://urlhaus.abuse.ch/",
            "free of charge under abuse.ch's fair use principles",
            "URLhaus, abuse.ch (https://urlhaus.abuse.ch)",
        ),
        Provider(
            "phishing",
            "Phishing.Database",
            "phishing",
            "phishing.sqlite",
            (
                Source(
                    "domains",
                    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
                    "master/phishing-domains-ACTIVE.txt",
                    "domain_list",
                    50_000,
                ),
                Source(
                    "addresses",
                    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
                    "master/phishing-IPs-ACTIVE.txt",
                    "address_list",
                    100,
                ),
            ),
            "https://github.com/Phishing-Database/Phishing.Database",
            "MIT",
            "Phishing.Database (https://github.com/Phishing-Database/Phishing.Database, "
            "MIT licence)",
        ),
        Provider(
            "feodo",
            "abuse.ch Feodo Tracker",
            "botnet",
            "feodo.sqlite",
            (
                Source(
                    "addresses",
                    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                    "address_list",
                    0,  # there are quiet times: an empty list is a real list...
                    trailer=True,  # ...but it says so, and counts what it holds
                ),
            ),
            "https://feodotracker.abuse.ch/blocklist/",
            "CC0",
            "Feodo Tracker, abuse.ch (https://feodotracker.abuse.ch)",
        ),
    )
}
URLS = tuple(source.url for provider in PROVIDERS.values() for source in provider.sources)


def attributions(keys: Collection[str] | None = None) -> list[str]:
    """How the data of the providers in ``keys`` (default: all) is credited."""
    return [p.attribution for p in PROVIDERS.values() if keys is None or p.key in keys]


@dataclass(frozen=True)
class FeedState:
    """What is installed of one provider."""

    key: str
    name: str
    kind: str  # malware | phishing | botnet
    as_of: str  # the day it was downloaded (ISO)
    published: str | None  # the day the file says it was written, when it says
    domains: int
    addresses: int
    stale: bool

    def to_data(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "as_of": self.as_of,
            "published": self.published,
            "domains": self.domains,
            "addresses": self.addresses,
            "stale": self.stale,
        }


@dataclass(frozen=True)
class Snapshot:
    """What is installed: the lists that can be read, and the providers whose file cannot."""

    feeds: tuple[FeedState, ...] = ()
    unreadable: tuple[str, ...] = ()

    @property
    def problem(self) -> str | None:
        return "unreadable" if self.unreadable else None


@dataclass(frozen=True)
class Listings:
    """Which providers list a name or an address (only those that are listed), and the providers
    whose file could not be read for this lookup (they are then not consulted)."""

    names: Mapping[str, tuple[str, ...]]
    addresses: Mapping[str, tuple[str, ...]]
    unreadable: tuple[str, ...] = ()


class BlocklistLookup(Protocol):
    """What the blocklist check needs (tests substitute a fake). ``only`` limits it to the
    providers the owner uses."""

    def snapshot(
        self, today: datetime.date | None = None, only: Collection[str] | None = None
    ) -> Snapshot: ...

    def lookup(
        self, names: Iterable[str], addresses: Iterable[str], only: Collection[str] | None = None
    ) -> Listings: ...


# --------------------------------------------------------------------------- reading the lists


def normalise_name(raw: str) -> str | None:
    """A host name as it is stored and looked up, or ``None`` if it is not one."""
    name = raw.strip().lower().rstrip(".")
    if not name or len(name) > 253 or not HOST.fullmatch(name):
        return None
    return name


def normalise_address(raw: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw.strip().strip("[]")))
    except ValueError:
        return None


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if len(line) <= MAX_LINE]


def _published(text: str) -> str | None:
    found = UPDATED.search(text[:2000])
    return found.group(1) if found else None


def parse_hostfile(text: str) -> tuple[set[str], set[str]]:
    """(names, addresses) of a hosts-file list: ``127.0.0.1<TAB>host`` lines and comments."""
    names: set[str] = set()
    addresses: set[str] = set()
    for line in _lines(text):
        content = line.split("#", 1)[0].split()
        if not content:
            continue
        found = content[-1]  # the first column is the address the file points the host at
        if (address := normalise_address(found)) is not None:
            addresses.add(address)
        elif (name := normalise_name(found)) is not None:
            names.add(name)
    return names, addresses


def parse_domain_list(text: str) -> set[str]:
    """The host names of a list with one per line (comments start with ``#``)."""
    found: set[str] = set()
    for line in _lines(text):
        content = line.split("#", 1)[0].strip()
        if content and (name := normalise_name(content)) is not None:
            found.add(name)
    return found


def parse_address_list(text: str) -> tuple[set[str], int | None]:
    """(addresses, the count the file declares in a ``# END n entries`` trailer, if it does)."""
    found: set[str] = set()
    for line in _lines(text):
        content = line.split("#", 1)[0].strip()
        if content and (address := normalise_address(content)) is not None:
            found.add(address)
    declared = DECLARED_COUNT.search(text[-400:])
    return found, int(declared.group(1)) if declared else None


# --------------------------------------------------------------------------- the database


def _read_source(source: Source, path: Path) -> tuple[set[str], set[str], str | None]:
    """(names, addresses, published) of a downloaded file, checked against what it should be."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DatasetError("unreadable_download") from exc
    if len(raw) > MAX_DOWNLOAD:
        raise DatasetError("download_too_large")
    if b"\x00" in raw[:4096]:
        raise DatasetError("not_text")
    text = raw.decode("utf-8", errors="replace")
    names: set[str] = set()
    addresses: set[str] = set()
    if source.parser == "hostfile":
        names, addresses = parse_hostfile(text)
    elif source.parser == "domain_list":
        names = parse_domain_list(text)
    else:
        addresses, declared = parse_address_list(text)
        if declared is None and source.trailer:
            raise DatasetError("no_trailer")  # cut short, or not the file it should be
        if declared is not None and declared != len(addresses):
            raise DatasetError("count_mismatch")
    return names, addresses, _published(text)


def build_database(
    provider: Provider,
    downloads: Mapping[str, Path],
    target: Path,
    now: datetime.datetime,
    *,
    relaxed: bool = False,
) -> FeedState:
    """Turn the downloaded files of ``provider`` into a SQLite file at ``target``.

    ``relaxed`` lowers the minimum sizes (tests build databases from small samples). The file at
    ``target`` is made afresh. Raises ``DatasetError`` with a stable reason when a file is not what
    it should be."""
    names: set[str] = set()
    addresses: set[str] = set()
    published: list[str] = []
    for source in provider.sources:
        found_names, found_addresses, written = _read_source(source, downloads[source.key])
        count = len(found_names) if source.key == "domains" else len(found_addresses)
        if count < (0 if relaxed else source.minimum):
            raise DatasetError("too_few_entries")
        names |= found_names
        addresses |= found_addresses
        if written:
            published.append(written)
    implausible = names & NEVER_LISTED
    if len(implausible) > MAX_IMPLAUSIBLE:
        raise DatasetError("implausible")
    names -= implausible
    if len(names) + len(addresses) > MAX_ROWS:
        raise DatasetError("too_many_rows")

    as_of = now.date().isoformat()
    target.unlink(missing_ok=True)  # an empty file left by mkstemp is fine, a built one is not
    connection = sqlite3.connect(target)
    try:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("CREATE TABLE domains (name TEXT PRIMARY KEY) WITHOUT ROWID")
        connection.execute("CREATE TABLE addresses (ip TEXT PRIMARY KEY) WITHOUT ROWID")
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.executemany("INSERT INTO domains VALUES (?)", ((n,) for n in sorted(names)))
        connection.executemany(
            "INSERT INTO addresses VALUES (?)", ((a,) for a in sorted(addresses))
        )
        connection.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [
                ("provider", provider.key),
                ("as_of", as_of),
                ("published", max(published) if published else ""),
                ("domains", str(len(names))),
                ("addresses", str(len(addresses))),
            ],
        )
        connection.commit()
    except sqlite3.Error as exc:
        raise DatasetError("not_a_database") from exc
    finally:
        connection.close()
    return FeedState(
        provider.key,
        provider.name,
        provider.kind,
        as_of,
        max(published) if published else None,
        len(names),
        len(addresses),
        False,
    )


def _open_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)


def installed_feed(provider: Provider, path: Path, today: datetime.date) -> FeedState | None:
    """The identity of an installed file, ``None`` if there is none or it is unreadable."""
    if not path.is_file():
        return None
    try:
        connection = _open_readonly(path)
        try:
            meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        finally:
            connection.close()
        as_of = datetime.date.fromisoformat(str(meta["as_of"]))
        return FeedState(
            provider.key,
            provider.name,
            provider.kind,
            as_of.isoformat(),
            str(meta.get("published") or "") or None,
            int(meta.get("domains", 0)),
            int(meta.get("addresses", 0)),
            (today - as_of).days > STALE_AFTER_DAYS,
        )
    except (sqlite3.Error, OSError, KeyError, ValueError):
        return None


# --------------------------------------------------------------------------- lookups


class BlocklistData:
    """The installed files, reread when they change (an update runs while workers keep going)."""

    def __init__(self, directory: Path, clock: Callable[[], datetime.date] | None = None) -> None:
        self._directory = directory
        self._today = clock or (lambda: datetime.datetime.now(datetime.UTC).date())
        self._lock = threading.Lock()
        self._feeds: dict[str, FeedState] = {}
        self._unreadable: set[str] = set()  # a file is there, but it cannot be read
        self._signature: tuple[Any, ...] | None = None
        self._checked = 0.0

    def _signatures(self) -> tuple[Any, ...]:
        parts: list[Any] = []
        for provider in PROVIDERS.values():
            try:
                stat = (self._directory / provider.filename).stat()
                parts.append((stat.st_size, stat.st_mtime_ns))
            except OSError:
                parts.append(None)
        return tuple(parts)

    def _refresh(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._signature is not None and now - self._checked < RELOAD_CHECK_SECONDS:
                return
            self._checked = now
            signature = self._signatures()
            if signature == self._signature:
                return
            feeds: dict[str, FeedState] = {}
            unreadable: set[str] = set()
            for provider, present in zip(PROVIDERS.values(), signature, strict=True):
                if present is None:
                    continue
                state = installed_feed(provider, self._directory / provider.filename, self._today())
                if state is None:
                    unreadable.add(provider.key)
                else:
                    feeds[provider.key] = state
            self._feeds = feeds
            self._unreadable = unreadable
            self._signature = signature

    def snapshot(
        self, today: datetime.date | None = None, only: Collection[str] | None = None
    ) -> Snapshot:
        """What is installed (of the providers in ``only``, if given) and how old it is."""
        self._refresh()
        today = today or self._today()
        feeds = tuple(
            FeedState(
                f.key,
                f.name,
                f.kind,
                f.as_of,
                f.published,
                f.domains,
                f.addresses,
                (today - datetime.date.fromisoformat(f.as_of)).days > STALE_AFTER_DAYS,
            )
            for f in self._feeds.values()
            if only is None or f.key in only
        )
        broken = [
            key for key in PROVIDERS if key in self._unreadable and (only is None or key in only)
        ]
        return Snapshot(feeds, tuple(broken))

    def lookup(
        self, names: Iterable[str], addresses: Iterable[str], only: Collection[str] | None = None
    ) -> Listings:
        """The providers that list each of ``names`` and ``addresses`` (only those listed)."""
        self._refresh()
        wanted_names = sorted({n for n in (normalise_name(x) for x in names) if n})
        wanted_addresses = sorted({a for a in (normalise_address(x) for x in addresses) if a})
        by_name: dict[str, list[str]] = {}
        by_address: dict[str, list[str]] = {}
        failed: list[str] = []
        for key in [k for k in self._feeds if only is None or k in only]:
            try:
                found_names, found_addresses = self._ask(key, wanted_names, wanted_addresses)
            except (sqlite3.Error, OSError):
                failed.append(key)  # nothing of this provider is used, not even a half answer
                continue
            for value in found_names:
                by_name.setdefault(value, []).append(key)
            for value in found_addresses:
                by_address.setdefault(value, []).append(key)
        if failed:  # read the files again next time: the provider is reported as unreadable then
            with self._lock:
                self._signature = None
        return Listings(
            {name: tuple(keys) for name, keys in by_name.items()},
            {address: tuple(keys) for address, keys in by_address.items()},
            tuple(failed),
        )

    def _ask(self, key: str, names: list[str], addresses: list[str]) -> tuple[list[str], list[str]]:
        """The ``names`` and ``addresses`` that provider ``key`` lists."""
        connection = _open_readonly(self._directory / PROVIDERS[key].filename)
        try:
            return (
                _matches(connection, "domains", "name", names),
                _matches(connection, "addresses", "ip", addresses),
            )
        finally:
            connection.close()


def _matches(
    connection: sqlite3.Connection, table: str, column: str, wanted: list[str]
) -> list[str]:
    found: list[str] = []
    for start in range(0, len(wanted), LOOKUP_BATCH):
        chunk = wanted[start : start + LOOKUP_BATCH]
        marks = ",".join("?" * len(chunk))
        query = f"SELECT {column} FROM {table} WHERE {column} IN ({marks})"  # noqa: S608
        found.extend(value for (value,) in connection.execute(query, chunk))
    return found


class NothingInstalled:
    """The lookup when there is no data directory to look in: nothing is known."""

    def snapshot(
        self, today: datetime.date | None = None, only: Collection[str] | None = None
    ) -> Snapshot:
        return Snapshot()

    def lookup(
        self, names: Iterable[str], addresses: Iterable[str], only: Collection[str] | None = None
    ) -> Listings:
        return Listings({}, {})


NOTHING = NothingInstalled()

_SHARED: dict[str, BlocklistData] = {}
_SHARED_LOCK = threading.Lock()


def shared(directory: Path) -> BlocklistData:
    """One reader per directory for the whole process (the worker's threads share it)."""
    key = str(directory.resolve())
    with _SHARED_LOCK:
        if key not in _SHARED:
            _SHARED[key] = BlocklistData(directory)
        return _SHARED[key]


# --------------------------------------------------------------------------- download and install


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


def _fetch(client: httpx.Client, url: str, destination: Path) -> tuple[int, str]:
    """Stream ``url`` into ``destination``, bounded; return (size, sha256)."""
    digest = hashlib.sha256()
    received = 0
    try:
        with (
            client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response,
            destination.open("wb") as out,
        ):
            if response.status_code != 200:
                raise DatasetError(f"http_{response.status_code}")
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_DOWNLOAD:
                raise DatasetError("download_too_large")
            for chunk in response.iter_bytes(CHUNK):
                received += len(chunk)
                if received > MAX_DOWNLOAD:
                    raise DatasetError("download_too_large")
                digest.update(chunk)
                out.write(chunk)
    except httpx.TimeoutException as exc:
        raise DatasetError("timeout") from exc
    except httpx.HTTPError as exc:
        raise DatasetError("connection_failed") from exc
    if received == 0:
        raise DatasetError("incomplete_download")
    return received, digest.hexdigest()


def _replace(temporary: Path, final: Path) -> None:
    """Move a checked file into place. On Windows a file that is being read cannot be replaced:
    try for a few seconds before giving up."""
    for attempt in range(25):
        try:
            os.replace(temporary, final)
            return
        except PermissionError:
            if attempt == 24:
                raise DatasetError("file_in_use") from None
            time.sleep(0.2)


def _recent(entry: object, now: datetime.datetime) -> bool:
    if not isinstance(entry, dict):
        return False
    try:
        downloaded = datetime.datetime.fromisoformat(str(entry.get("downloaded_at")))
    except ValueError:
        return False
    return now - downloaded < REFRESH_AFTER


def _temporary(directory: Path, kind: str, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{kind}-", suffix=suffix)
    os.close(descriptor)
    return Path(name)


def _update_provider(
    provider: Provider,
    directory: Path,
    client: httpx.Client,
    now: datetime.datetime,
    force: bool,
    manifest: dict[str, Any],
    *,
    relaxed: bool,
) -> UpdateReport:
    final = directory / provider.filename
    existing = installed_feed(provider, final, now.date())
    if not force and existing is not None and _recent(manifest.get(provider.key), now):
        return UpdateReport(provider.key, "current", f"as of {existing.as_of}")
    downloads = {
        source.key: _temporary(directory, provider.key, ".txt") for source in provider.sources
    }
    database = _temporary(directory, provider.key, ".sqlite")
    sizes: list[int] = []
    digests: list[str] = []
    try:
        for source in provider.sources:
            size, sha256 = _fetch(client, source.url, downloads[source.key])
            sizes.append(size)
            digests.append(sha256)
        feed = build_database(provider, downloads, database, now, relaxed=relaxed)
        _replace(database, final)
    except DatasetError as exc:
        return UpdateReport(provider.key, "failed", f"{provider.name}: {exc.reason}")
    finally:
        for path in (*downloads.values(), database):
            path.unlink(missing_ok=True)
    combined = hashlib.sha256("".join(digests).encode("ascii")).hexdigest()
    manifest[provider.key] = {
        "file": provider.filename,
        "source": ", ".join(source.url for source in provider.sources),
        "downloaded_at": now.isoformat(timespec="seconds"),
        "sha256": combined,
        "size": sum(sizes),
        "build": feed.as_of,
        "published": feed.published,
        "domains": feed.domains,
        "addresses": feed.addresses,
    }
    detail = f"as of {feed.as_of}, {feed.domains:,} hosts and {feed.addresses:,} addresses"
    return UpdateReport(
        provider.key, "updated", detail, provider.sources[0].url, None, sum(sizes), combined
    )


def update(
    directory: Path,
    client: httpx.Client,
    *,
    now: datetime.datetime | None = None,
    force: bool = False,
    relaxed: bool = False,
    only: Collection[str] | None = None,
) -> list[UpdateReport]:
    """Bring the lists of the providers in ``only`` (default: all three) up to date; each is tried
    even if another one failed."""
    now = now or datetime.datetime.now(datetime.UTC)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(directory)
    reports = [
        _update_provider(provider, directory, client, now, force, manifest, relaxed=relaxed)
        for provider in PROVIDERS.values()
        if only is None or provider.key in only
    ]
    write_manifest(directory, manifest)
    return reports


def status(
    directory: Path, *, today: datetime.date | None = None, only: Collection[str] | None = None
) -> list[DatasetStatus]:
    """What is installed (of the providers in ``only``, default all), how old it is and where it
    came from."""
    today = today or datetime.datetime.now(datetime.UTC).date()
    manifest = read_manifest(directory)
    result: list[DatasetStatus] = []
    for provider in PROVIDERS.values():
        if only is not None and provider.key not in only:
            continue
        path = directory / provider.filename
        feed = installed_feed(provider, path, today)
        if feed is None:
            problem = "unreadable" if path.exists() else "not installed"
            result.append(
                DatasetStatus(provider.key, False, None, None, False, None, None, problem)
            )
            continue
        raw = manifest.get(provider.key)
        entry: dict[str, Any] = raw if isinstance(raw, dict) else {}
        age = (today - datetime.date.fromisoformat(feed.as_of)).days
        result.append(
            DatasetStatus(
                provider.key,
                True,
                feed.as_of,
                age,
                feed.stale,
                entry.get("source"),
                entry.get("sha256"),
                None,
            )
        )
    return result
