"""Tiny MMDB files shaped like the real DB-IP Lite databases (checked against the real files).

Built with ``mmdb-writer`` so tests need neither the network nor the 127 MB city database.
"""

from __future__ import annotations

import datetime
import gzip
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mmdb_writer import MMDBWriter
from netaddr import IPSet

CITY_TYPE = "DBIP-City-Lite"
ASN_TYPE = "DBIP-ASN-Lite"


def place(
    country: str,
    country_name: str,
    city: str | None = None,
    region: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
    continent: str = "EU",
) -> dict[str, Any]:
    """A city-database record in DB-IP's (GeoIP2-compatible) layout."""
    record: dict[str, Any] = {
        "continent": {"code": continent, "names": {"en": continent}},
        "country": {"iso_code": country, "names": {"en": country_name}},
    }
    if city:
        record["city"] = {"names": {"en": city}}
    if region:
        record["subdivisions"] = [{"names": {"en": region}}]
    if latitude is not None and longitude is not None:
        record["location"] = {"latitude": latitude, "longitude": longitude}
    return record


def network(number: int, organisation: str) -> dict[str, Any]:
    """An ASN-database record."""
    return {"autonomous_system_number": number, "autonomous_system_organization": organisation}


class _Writer(MMDBWriter):
    """An MMDB writer whose build date can be chosen."""

    built: datetime.date | None = None

    def _build_meta(self) -> dict[str, Any]:
        meta = super()._build_meta()
        if self.built is not None:
            moment = datetime.datetime.combine(self.built, datetime.time(1, 0), datetime.UTC)
            meta["build_epoch"] = int(moment.timestamp())
        return meta


def write_mmdb(
    path: Path,
    database_type: str,
    records: Mapping[str, dict[str, Any]],
    *,
    built: datetime.date | None = None,
    ip_version: int = 6,
) -> Path:
    writer = _Writer(
        ip_version=ip_version,
        ipv4_compatible=ip_version == 6,
        database_type=database_type,
        languages=["en"],
        description={"en": "test database"},
    )
    writer.built = built
    for cidr, record in records.items():
        writer.insert_network(IPSet([cidr]), record)
    path.parent.mkdir(parents=True, exist_ok=True)
    writer.to_db_file(str(path))
    return path


CITY_RECORDS: dict[str, dict[str, Any]] = {
    "8.8.8.0/24": place("US", "United States", "Mountain View", "California", 37.4, -122.1, "NA"),
    "85.1.1.0/24": place("CH", "Switzerland", "Bern", "Bern", 46.85, 7.68),
    "46.4.0.0/16": place("DE", "Germany", "Falkenstein", "Saxony", 50.48, 12.37),
    "104.21.58.0/24": place("CA", "Canada", "Toronto", "Ontario", 43.65, -79.38, "NA"),
    "2606:4700:3035::/48": place("CA", "Canada", "Toronto", "Ontario", 43.65, -79.38, "NA"),
    "93.184.216.0/24": place("GB", "United Kingdom", "London", None, 51.5, -0.12),
}
ASN_RECORDS: dict[str, dict[str, Any]] = {
    "8.8.8.0/24": network(15169, "Google LLC"),
    "85.1.1.0/24": network(3303, "Swisscom (Schweiz) AG"),
    "46.4.0.0/16": network(24940, "Hetzner Online GmbH"),
    "104.21.58.0/24": network(13335, "Cloudflare, Inc."),
    "2606:4700:3035::/48": network(13335, "Cloudflare, Inc."),
    "5.9.0.0/16": network(24940, "Hetzner Online GmbH"),  # ASN known, no city record
}


def install_databases(
    directory: Path,
    *,
    built: datetime.date | None = None,
    city: Mapping[str, dict[str, Any]] | None = None,
    asn: Mapping[str, dict[str, Any]] | None = None,
) -> Path:
    """Write both databases under their installed names."""
    write_mmdb(directory / "dbip-city-lite.mmdb", CITY_TYPE, city or CITY_RECORDS, built=built)
    write_mmdb(directory / "dbip-asn-lite.mmdb", ASN_TYPE, asn or ASN_RECORDS, built=built)
    return directory


def gzipped(path: Path) -> bytes:
    """What the download servers send: the database, gzip-compressed."""
    return gzip.compress(path.read_bytes())
