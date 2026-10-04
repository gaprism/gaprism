"""Offline IP lookups from the DB-IP Lite databases (city and ASN), reopened when they change.

The databases are updated by ``flask datasets update`` (see ``datasets.py``) while workers keep
running, so every file is checked for changes (cheaply, at most every ``RELOAD_CHECK_SECONDS``)
and reopened when it was replaced. On Windows a memory-mapped file cannot be replaced, so the
whole file is read into memory there; elsewhere it is mapped.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import maxminddb
from maxminddb import Reader
from maxminddb.errors import InvalidDatabaseError

from app.service.geo.models import DatabaseInfo, GeoUnavailableError, IpLocation

CITY_FILE = "dbip-city-lite.mmdb"
ASN_FILE = "dbip-asn-lite.mmdb"
RELOAD_CHECK_SECONDS = 30.0
MAX_NAME_LENGTH = 100


def _open_mode() -> int:
    return maxminddb.MODE_MEMORY if os.name == "nt" else maxminddb.MODE_AUTO


def _name(value: object) -> str | None:
    """The English name of a ``{"names": {...}}`` entry (or the first one there is)."""
    if not isinstance(value, Mapping):
        return None
    names = value.get("names")
    if not isinstance(names, Mapping) or not names:
        return None
    chosen = names.get("en") or next(iter(names.values()))
    return str(chosen)[:MAX_NAME_LENGTH] if chosen else None


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


class _Database:
    """One database file; reopened when its size or modification time changes."""

    def __init__(self, path: Path, kind: str) -> None:
        self.path = path
        self.kind = kind
        self._reader: Reader | None = None
        self._signature: tuple[int, int] | None = None
        self._checked = 0.0
        self._lock = threading.Lock()

    def reader(self) -> Reader | None:
        """The open reader, ``None`` if the file does not exist; raises when it is unusable."""
        with self._lock:
            now = time.monotonic()
            if self._reader is not None and now - self._checked < RELOAD_CHECK_SECONDS:
                return self._reader
            self._checked = now
            try:
                stat = self.path.stat()
            except FileNotFoundError:
                self._reader, self._signature = None, None
                return None
            signature = (stat.st_size, stat.st_mtime_ns)
            if self._reader is None or signature != self._signature:
                try:
                    self._reader = maxminddb.open_database(str(self.path), mode=_open_mode())
                except (InvalidDatabaseError, ValueError, OSError) as exc:
                    self._reader, self._signature = None, None
                    raise GeoUnavailableError("datasets_unreadable") from exc
                self._signature = signature
            return self._reader

    def info(self) -> DatabaseInfo | None:
        reader = self.reader()
        if reader is None:
            return None
        meta = reader.metadata()
        build = datetime.datetime.fromtimestamp(meta.build_epoch, datetime.UTC).date()
        return DatabaseInfo(self.kind, str(meta.database_type), build.isoformat())


class DbIpProvider:
    """City and ASN lookups from the files in ``directory``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._city = _Database(directory / CITY_FILE, "city")
        self._asn = _Database(directory / ASN_FILE, "asn")

    def lookup(self, ip: str) -> IpLocation:
        """What the databases know about ``ip``.

        Raises ``ValueError`` for something that is not an address and ``GeoUnavailableError`` when
        no database can be read. An address the databases do not know is an ``IpLocation`` with
        nothing in it (``found`` is False), not an error.
        """
        parsed = ipaddress.ip_address(ip.strip("[]"))
        city, asn = self._city.reader(), self._asn.reader()
        if city is None and asn is None:
            raise GeoUnavailableError("datasets_missing")
        fields: dict[str, Any] = {}
        if city is not None:
            fields.update(self._from_city(self._get(city, parsed)))
        if asn is not None:
            fields.update(self._from_asn(self._get(asn, parsed)))
        return IpLocation(ip=str(parsed), **fields)

    @staticmethod
    def _get(reader: Reader, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> object:
        try:
            return reader.get(address)
        except InvalidDatabaseError as exc:
            raise GeoUnavailableError("datasets_unreadable") from exc
        except ValueError:
            return None  # an IPv6 address asked of an IPv4-only database: it does not know it

    @staticmethod
    def _from_city(record: object) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            return {}
        country = record.get("country") if isinstance(record.get("country"), Mapping) else {}
        continent = record.get("continent") if isinstance(record.get("continent"), Mapping) else {}
        location = record.get("location") if isinstance(record.get("location"), Mapping) else {}
        subdivisions = record.get("subdivisions")
        iso = country.get("iso_code") if isinstance(country, Mapping) else None
        code = continent.get("code") if isinstance(continent, Mapping) else None
        return {
            "country": iso.upper() if isinstance(iso, str) and len(iso) == 2 else None,
            "country_name": _name(country),
            "continent": code if isinstance(code, str) else None,
            "region": _name(subdivisions[0])
            if isinstance(subdivisions, list) and subdivisions
            else None,
            "city": _name(record.get("city")),
            "latitude": _number(location.get("latitude"))
            if isinstance(location, Mapping)
            else None,
            "longitude": _number(location.get("longitude"))
            if isinstance(location, Mapping)
            else None,
        }

    @staticmethod
    def _from_asn(record: object) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            return {}
        number = record.get("autonomous_system_number")
        organisation = record.get("autonomous_system_organization")
        return {
            "asn": number if isinstance(number, int) and not isinstance(number, bool) else None,
            "organisation": str(organisation)[:MAX_NAME_LENGTH] if organisation else None,
        }

    def databases(self) -> list[DatabaseInfo]:
        """The databases that are present (city first)."""
        found = (self._city.info(), self._asn.info())
        return [info for info in found if info is not None]


class ProviderCache:
    """One provider per directory, shared by every thread of the process."""

    def __init__(self) -> None:
        self._providers: dict[Path, DbIpProvider] = {}
        self._lock = threading.Lock()

    def get(self, directory: Path) -> DbIpProvider:
        key = directory.resolve()
        with self._lock:
            if key not in self._providers:
                self._providers[key] = DbIpProvider(key)
            return self._providers[key]


SHARED_PROVIDERS = ProviderCache()
