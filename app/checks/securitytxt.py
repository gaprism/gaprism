"""security.txt (RFC 9116): does the domain say how to report a vulnerability, and is it current?

A domain-level check that fetches the file through the egress gate (screened address, IP-pinned,
verified certificate, 64 KB, three redirects at most). The places tried are ``/.well-known/`` and
the site root on the domain, then the same on ``www.`` when the domain itself has no web server.
A page that merely answers 200 (a "not found" page with a status code of 200) is not a
security.txt: it needs a recognised field and must not be HTML.

The file is read for the facts an analyst cares about: contacts, expiry, encryption key, policy,
whether it is signed, and what is wrong with it. Free text and comments are never kept.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.fetch import (
    ClientFactory,
    NameResolver,
    default_client,
    default_names,
    fetch_document,
)

LOCATIONS = ("/.well-known/security.txt", "/security.txt")
FIELDS = (
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
    "csaf",
)
MAX_VALUES = 10
MAX_VALUE = 300
MAX_LINES = 500
BUDGET_SECONDS = 60.0
_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----"
_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"


def parse_security_txt(text: str) -> dict[str, Any]:
    """The known fields of a security.txt (several values per field), and whether it is signed."""
    signed = _SIGNED in text
    body = text
    if signed:
        body = text.split(_SIGNED, 1)[1]
        _, _, body = body.partition("\n\n")  # skip the armor headers (Hash: ...)
        body = body.split(_SIGNATURE, 1)[0]
    fields: dict[str, list[str]] = {}
    for line in body.splitlines()[:MAX_LINES]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, value = stripped.partition(":")
        key = name.strip().lower()
        if separator and key in FIELDS:
            values = fields.setdefault(key, [])
            if len(values) < MAX_VALUES:
                values.append("".join(ch for ch in value.strip() if ch.isprintable())[:MAX_VALUE])
    return {"signed": signed, "fields": fields}


def parse_expires(value: str) -> datetime | None:
    """An RFC 3339 date-time; a lower-case ``z`` or ``t`` is allowed by the RFC (and is common)."""
    cleaned = re.sub(r"[tz]", lambda m: m.group().upper(), value.strip())
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _within(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def analyse(
    parsed: dict[str, Any],
    *,
    url: str,
    domain: str,
    content_type: str,
    now: datetime,
) -> dict[str, Any]:
    """Facts and problems of a found file (``url`` is where it was finally served)."""
    fields: dict[str, list[str]] = parsed["fields"]
    problems: list[str] = []
    if not fields.get("contact"):
        problems.append("missing_contact")
    expires: datetime | None = None
    values = fields.get("expires", [])
    if not values:
        problems.append("missing_expires")
    else:
        if len(values) > 1:
            problems.append("multiple_expires")
        expires = parse_expires(values[0])
        if expires is None:
            problems.append("invalid_expires")
        elif expires < now:
            problems.append("expired")
    if "text/plain" not in content_type.lower():
        problems.append("not_plain_text")
    parts = urlsplit(url)
    if parts.scheme != "https":
        problems.append("not_https")
    if not _within(parts.hostname or "", domain):
        problems.append("offsite")
    canonical = fields.get("canonical", [])
    if canonical and url not in canonical:
        problems.append("canonical_mismatch")
    return {
        "url": url,
        "signed": parsed["signed"],
        "fields": fields,
        "expires": expires.astimezone(UTC).isoformat() if expires else None,
        "days_to_expiry": (expires - now).days if expires else None,
        "problems": problems,
    }


class SecurityTxtCheck:
    """Find and read the domain's security.txt."""

    key = "security_txt"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        name_resolver: NameResolver | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_factory = client_factory or default_client
        self._names = name_resolver or default_names
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = ctx.domain.lower().rstrip(".")
        names = self._names

        def resolve(name: str) -> list[str]:
            return names(ctx.config, name)

        client = self._client_factory(ctx.config, resolve)
        deadline = self._monotonic() + BUDGET_SECONDS
        tried: list[dict[str, Any]] = []
        for host in (domain, f"www.{domain}"):
            for path in LOCATIONS:
                if self._monotonic() > deadline:
                    tried.append({"url": f"https://{host}{path}", "error": "budget_exceeded"})
                    continue
                found = self._try(client, f"https://{host}{path}", domain, tried)
                if found is not None:
                    return CheckOutcome("ok", data={**found, "tried": tried}, source="https")
            if self._answered(tried, domain):
                break  # the domain's own web server answered: do not wander to www
        data = {"domain": domain, "tried": tried}
        errors = [t["error"] for t in tried if t.get("error")]
        if self._answered(tried, domain) or not errors:
            return CheckOutcome("no_data", "no_security_txt", data, "https")
        return CheckOutcome("error", errors[0], data, "https")

    def _try(
        self, client: Any, url: str, domain: str, tried: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        document = fetch_document(client, url, {"Accept": "text/plain, */*;q=0.5"})
        entry: dict[str, Any] = {"url": url, "status": None, "error": document.error}
        tried.append(entry)
        response = document.response
        if response is None:
            return None
        entry["status"] = response.status_code
        if response.status_code != 200 or document.redirect_limit:
            return None
        text = response.text
        parsed = parse_security_txt(text)
        if text.lstrip().startswith("<") or not parsed["fields"]:
            entry["status"], entry["error"] = 200, "not_security_txt"
            return None
        content_type = response.headers.get("content-type", "")
        found = analyse(
            parsed, url=response.url, domain=domain, content_type=content_type, now=self._clock()
        )
        found["requested"] = url
        found["hops"] = document.hops
        found["truncated"] = response.truncated
        return found

    @staticmethod
    def _answered(tried: list[dict[str, Any]], domain: str) -> bool:
        """Did the domain's own web server (not ``www``) answer with an HTTP status?"""
        own = [t for t in tried if urlsplit(t["url"]).hostname == domain]
        return any(t.get("status") is not None for t in own)
