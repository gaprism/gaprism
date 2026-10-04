"""Certificate Transparency (CT) log discovery adapter and host extraction."""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from app.service.discovery.scope import canonicalise_domain

logger = logging.getLogger(__name__)


class CTDiscoveryError(Exception):
    """Raised when Certificate Transparency query or parsing fails."""


@dataclass(frozen=True)
class CTEntry:
    """Discovered Certificate Transparency record or pattern."""

    name: str
    entry_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_wildcard: bool = False


@dataclass(frozen=True)
class CTPagedResult:
    """Standardised result envelope for a CT discovery page query."""

    entries: list[CTEntry]
    next_cursor: str | None = None
    total_found: int | None = None
    has_more: bool = False


class CTDiscoveryAdapter:
    """Adapter for querying public Certificate Transparency logs and parsing names."""

    def __init__(
        self,
        base_url: str = "https://api.ctlogs.dev/v1",
        timeout: float = 15.0,
        http_client: httpx.Client | None = None,
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = http_client
        self._api_key = api_key

    def fetch_page(
        self,
        domain_ascii: str,
        cursor: str | None = None,
        limit: int = 100,
    ) -> CTPagedResult:
        """Fetch a single page of Certificate Transparency log records for a domain."""
        domain = canonicalise_domain(domain_ascii).canonical
        if not 1 <= limit <= 100:
            raise ValueError("CT page limit must be between 1 and 100.")
        url = f"{self.base_url}/hosts/{domain}"
        params: dict[str, str | int] = {"limit": limit}
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        if cursor:
            params["after"] = cursor

        client = self._client or httpx.Client(
            timeout=self.timeout, trust_env=False, follow_redirects=False
        )
        try:
            response = client.get(url, params=params, headers=headers, follow_redirects=False)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or "hosts" not in data:
                raise CTDiscoveryError("CT API returned an unexpected hosts response.")
            return self.parse_ct_response(data)
        except CTDiscoveryError:
            raise
        except httpx.HTTPStatusError as exc:
            raise CTDiscoveryError(f"CT API HTTP {exc.response.status_code}") from None
        except (httpx.RequestError, ValueError):
            raise CTDiscoveryError("CT query failed or returned invalid JSON.") from None
        finally:
            if self._client is None:
                client.close()

    @staticmethod
    def parse_ct_response(data: dict[str, Any]) -> CTPagedResult:
        """Parse varied CT JSON payload structures into standard CTPagedResult."""
        if not isinstance(data, dict):
            raise CTDiscoveryError("CT response must be an object.")
        if "hosts" in data:
            hosts = data["hosts"]
            cursor = data.get("next_cursor") or None
            has_next = data.get("has_next")
            if (
                not isinstance(hosts, list)
                or not isinstance(has_next, bool)
                or (cursor is not None and not isinstance(cursor, str))
                or has_next != bool(cursor)
            ):
                raise CTDiscoveryError("Invalid CT hosts pagination envelope.")
            parsed_entries = []
            for row in hosts:
                if not isinstance(row, dict) or not isinstance(row.get("host"), str):
                    raise CTDiscoveryError("Invalid CT hostname row.")
                name = row["host"].strip().lower()
                count = row.get("certs")
                if not name or type(count) is not int or count < 1:
                    raise CTDiscoveryError("Invalid CT hostname or certificate count.")
                times = []
                for field in ("first_seen", "last_seen"):
                    try:
                        value = datetime.fromisoformat(row[field]) if row.get(field) else None
                        if value is not None and value.tzinfo is None:
                            raise ValueError("missing timezone")
                    except (ValueError, TypeError):
                        raise CTDiscoveryError("Invalid CT observation timestamp.") from None
                    times.append(value)
                parsed_entries.append(
                    CTEntry(name, count, times[0], times[1], name.startswith("*."))
                )
            return CTPagedResult(parsed_entries, cursor, has_more=has_next)
        if not any(key in data for key in ("items", "certificates", "names")):
            raise CTDiscoveryError("Unrecognised CT response schema.")
        entries: list[CTEntry] = []
        next_cursor: str | None = data.get("next_cursor") or data.get("cursor")

        # 1. Structure: {"items": [{"name": "...", "count": 1, ...}]}
        if "items" in data and isinstance(data["items"], list):
            for item in data["items"]:
                if isinstance(item, dict) and "name" in item:
                    name = str(item["name"]).strip().lower()
                    if not name:
                        continue
                    first_seen = None
                    last_seen = None
                    if item.get("first_seen"):
                        with contextlib.suppress(ValueError):
                            first_seen = datetime.fromisoformat(str(item["first_seen"]))
                    if item.get("last_seen"):
                        with contextlib.suppress(ValueError):
                            last_seen = datetime.fromisoformat(str(item["last_seen"]))
                    entries.append(
                        CTEntry(
                            name=name,
                            entry_count=int(item.get("count", 1)),
                            first_seen=first_seen,
                            last_seen=last_seen,
                            is_wildcard=name.startswith("*.") or name == "*",
                        )
                    )

        # 2. Structure: {"certificates": [{"dns_names": ["a.com", "*.a.com"]}]}
        elif "certificates" in data and isinstance(data["certificates"], list):
            for cert in data["certificates"]:
                if isinstance(cert, dict):
                    dns_names = cert.get("dns_names", [])
                    if isinstance(dns_names, list):
                        for name_raw in dns_names:
                            name = str(name_raw).strip().lower()
                            if not name:
                                continue
                            entries.append(
                                CTEntry(
                                    name=name,
                                    entry_count=1,
                                    is_wildcard=name.startswith("*.") or name == "*",
                                )
                            )

        # 3. Flat string list: {"names": ["a.example.com", ...]}
        elif "names" in data and isinstance(data["names"], list):
            for name_raw in data["names"]:
                name = str(name_raw).strip().lower()
                if not name:
                    continue
                entries.append(
                    CTEntry(
                        name=name,
                        entry_count=1,
                        is_wildcard=name.startswith("*.") or name == "*",
                    )
                )

        has_more = bool(next_cursor)
        return CTPagedResult(
            entries=entries,
            next_cursor=next_cursor,
            total_found=data.get("total_count"),
            has_more=has_more,
        )
