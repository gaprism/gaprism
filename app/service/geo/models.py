"""What the offline databases tell us about an IP address."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class GeoUnavailableError(Exception):
    """No usable database; ``reason_code`` is ``datasets_missing`` or ``datasets_unreadable``."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class IpLocation:
    """Location and network of one IP address. Every field may be missing.

    The location is where the address is *registered or announced*, usually a data centre but,
    for CDN and anycast networks, an edge site: callers must not read it as "where the data is"
    without looking at the network hint.
    """

    ip: str
    country: str | None = None  # ISO 3166-1 alpha-2, upper case
    country_name: str | None = None
    continent: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    organisation: str | None = None

    @property
    def found(self) -> bool:
        """True if either database knew the address."""
        return self.country is not None or self.asn is not None

    def to_data(self) -> dict[str, Any]:
        return {
            "country": self.country,
            "country_name": self.country_name,
            "continent": self.continent,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "organisation": self.organisation,
        }


@dataclass(frozen=True)
class DatabaseInfo:
    """One database file as the provider sees it."""

    kind: str  # city | asn
    database_type: str
    build: str  # ISO date of the database build

    def to_data(self) -> dict[str, str]:
        return {"kind": self.kind, "type": self.database_type, "build": self.build}
