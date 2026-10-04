"""Certificate Transparency (CT) log discovery adapter and host extraction."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.discovery import CTNameObservation, Host, RunHost
from app.models.scan_run import ScanRun
from app.service.discovery.scope import DomainScope, canonicalise_domain, is_in_scope

logger = logging.getLogger(__name__)

MAX_HOSTS_PER_RUN_DEFAULT = 1000
MAX_DISCOVERY_PAGES_DEFAULT = 50


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
                        try:
                            first_seen = datetime.fromisoformat(str(item["first_seen"]))
                        except Exception:
                            pass
                    if item.get("last_seen"):
                        try:
                            last_seen = datetime.fromisoformat(str(item["last_seen"]))
                        except Exception:
                            pass
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


@dataclass(frozen=True)
class DiscoveryPageCommitResult:
    """Summary of database records committed from a discovery page."""

    discovered_names_count: int
    new_concrete_hosts_count: int
    wildcard_patterns_count: int
    cap_reached: bool
    next_cursor: str | None


def commit_discovery_page(
    session: Session,
    workspace_id: uuid.UUID,
    assessment_id: uuid.UUID,
    run_id: uuid.UUID,
    scope: DomainScope | str,
    page_result: CTPagedResult,
    max_hosts_per_run: int = MAX_HOSTS_PER_RUN_DEFAULT,
) -> DiscoveryPageCommitResult:
    """Atomically commit a discovery page's observations and hosts into the database.

    Enforces invariants:
    - INV-03: Every fact records subject, source, and collection time.
    - INV-05: Wildcard certificate patterns are saved as CTNameObservation patterns,
              NEVER converted to concrete Host targets.
    - Host cap enforcement: Stops creating eligible run hosts once max_hosts_per_run is reached.
    """
    now = datetime.now(UTC)
    new_hosts_count = 0
    wildcard_count = 0
    discovered_count = 0

    # Count existing hosts attached to this run
    current_run_hosts_count = (
        session.scalar(select(func.count(RunHost.id)).where(RunHost.run_id == run_id)) or 0
    )

    cap_reached = current_run_hosts_count >= max_hosts_per_run

    # Deduplicate entries in this page by name
    unique_entries: dict[str, CTEntry] = {}
    for entry in page_result.entries:
        cleaned_name = entry.name.strip().rstrip(".").lower()
        if not cleaned_name:
            continue
        if cleaned_name not in unique_entries:
            unique_entries[cleaned_name] = entry
        else:
            # Accumulate count
            existing = unique_entries[cleaned_name]
            unique_entries[cleaned_name] = CTEntry(
                name=existing.name,
                entry_count=existing.entry_count + entry.entry_count,
                first_seen=existing.first_seen or entry.first_seen,
                last_seen=entry.last_seen or existing.last_seen,
                is_wildcard=existing.is_wildcard or entry.is_wildcard,
            )

    for clean_name, entry in unique_entries.items():
        discovered_count += 1
        is_wildcard = entry.is_wildcard or clean_name.startswith("*.") or clean_name == "*"

        # 1. Always record CTNameObservation (Wildcard or Concrete)
        existing_obs = session.scalar(
            select(CTNameObservation).where(
                CTNameObservation.run_id == run_id,
                CTNameObservation.name_pattern == clean_name,
            )
        )
        if existing_obs:
            existing_obs.entry_count += entry.entry_count
            if entry.last_seen:
                existing_obs.last_seen = entry.last_seen
        else:
            obs = CTNameObservation(
                workspace_id=workspace_id,
                assessment_id=assessment_id,
                run_id=run_id,
                name_pattern=clean_name,
                is_wildcard=is_wildcard,
                entry_count=entry.entry_count,
                first_seen=entry.first_seen,
                last_seen=entry.last_seen,
            )
            session.add(obs)

        # 2. If it is a wildcard pattern, NEVER create a concrete Host (INV-05)
        if is_wildcard:
            wildcard_count += 1
            continue

        # 3. Check domain scope boundary
        if not is_in_scope(clean_name, scope):
            continue

        # 4. Check / Insert Host in Assessment inventory
        host = session.scalar(
            select(Host).where(
                Host.assessment_id == assessment_id,
                Host.name_ascii == clean_name,
            )
        )
        if not host:
            host = Host(
                workspace_id=workspace_id,
                assessment_id=assessment_id,
                name_ascii=clean_name,
                name_display=clean_name,
            )
            session.add(host)
            session.flush()

        # 5. Check / Insert RunHost association
        run_host = session.scalar(
            select(RunHost).where(
                RunHost.run_id == run_id,
                RunHost.host_id == host.id,
            )
        )
        if not run_host:
            if not cap_reached and (current_run_hosts_count + new_hosts_count < max_hosts_per_run):
                eligibility = "eligible"
                exclusion_reason = None
                new_hosts_count += 1
            else:
                eligibility = "excluded"
                exclusion_reason = "run_host_cap_exceeded"
                cap_reached = True

            run_host = RunHost(
                workspace_id=workspace_id,
                assessment_id=assessment_id,
                run_id=run_id,
                host_id=host.id,
                discovery_source="ct_log",
                eligibility=eligibility,
                exclusion_reason=exclusion_reason,
                first_collected_at=now,
            )
            session.add(run_host)

    # Update scan_run total discovered count
    scan_run = session.scalar(select(ScanRun).where(ScanRun.id == run_id))
    if scan_run:
        scan_run.total_hosts_discovered = current_run_hosts_count + new_hosts_count

    return DiscoveryPageCommitResult(
        discovered_names_count=discovered_count,
        new_concrete_hosts_count=new_hosts_count,
        wildcard_patterns_count=wildcard_count,
        cap_reached=cap_reached,
        next_cursor=page_result.next_cursor,
    )
