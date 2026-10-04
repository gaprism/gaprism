"""What an internet-wide scan database (Shodan, InternetDB) reports about an IP address."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

LookupStatus = Literal["ok", "no_data", "unavailable", "error"]

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
MAX_SERVICES = 100
MAX_VULNERABILITIES = 200
MAX_TEXT = 300
MAX_LIST = 50


def clean_text(value: object, limit: int = MAX_TEXT) -> str | None:
    """A bounded string without control characters, or ``None``."""
    if not isinstance(value, str) or not value.strip():
        return None
    return "".join(ch for ch in value if ch.isprintable())[:limit] or None


def clean_list(value: object, limit: int = MAX_LIST) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    items = (clean_text(item, 253) for item in value[: limit * 2])
    return tuple(item for item in items if item)[:limit]


@dataclass(frozen=True)
class PortService:
    port: int
    transport: str | None = None  # tcp | udp, when the source says
    product: str | None = None
    version: str | None = None
    cpe: tuple[str, ...] = ()

    def to_data(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "transport": self.transport,
            "product": self.product,
            "version": self.version,
            "cpe": list(self.cpe),
        }


@dataclass(frozen=True)
class Vulnerability:
    id: str
    cvss: float | None = None
    summary: str | None = None
    verified: bool | None = None  # Shodan marks CVEs it confirmed

    def to_data(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "summary": self.summary,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class PortFacts:
    """Everything one provider knows about one address (already bounded and cleaned)."""

    ip: str
    provider: str
    services: tuple[PortService, ...] = ()
    vulnerabilities: tuple[Vulnerability, ...] = ()
    hostnames: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()  # InternetDB lists CPEs for the address, not per port
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    os: str | None = None
    last_update: str | None = None

    @property
    def ports(self) -> list[int]:
        return sorted({service.port for service in self.services})

    def to_data(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "provider": self.provider,
            "ports": self.ports,
            "services": [service.to_data() for service in self.services],
            "vulnerabilities": [vuln.to_data() for vuln in self.vulnerabilities],
            "hostnames": list(self.hostnames),
            "tags": list(self.tags),
            "cpes": list(self.cpes),
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "os": self.os,
            "last_update": self.last_update,
        }

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> PortFacts:
        """Rebuild from ``to_data`` (the provider cache stores that form)."""
        return cls(
            ip=str(data["ip"]),
            provider=str(data["provider"]),
            services=tuple(
                PortService(
                    int(item["port"]),
                    item.get("transport"),
                    item.get("product"),
                    item.get("version"),
                    tuple(item.get("cpe", [])),
                )
                for item in data.get("services", [])
            ),
            vulnerabilities=tuple(
                Vulnerability(
                    str(item["id"]), item.get("cvss"), item.get("summary"), item.get("verified")
                )
                for item in data.get("vulnerabilities", [])
            ),
            hostnames=tuple(data.get("hostnames", [])),
            tags=tuple(data.get("tags", [])),
            cpes=tuple(data.get("cpes", [])),
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            os=data.get("os"),
            last_update=data.get("last_update"),
        )


@dataclass(frozen=True)
class PortsLookup:
    """The outcome of asking a provider about one address."""

    status: LookupStatus
    reason: str | None = None
    facts: PortFacts | None = field(default=None)
