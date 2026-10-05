"""Public breach history of the domain, from Have I Been Pwned (the ``breaches`` endpoint).

A domain-level check. HIBP lists breaches of *services* by the service's domain, so the question
here is "has a service on this domain been breached, publicly, in a way someone documented": it
says nothing about breaches that were never made public, and nothing about the vendor's own
accounts elsewhere. The endpoint needs no key. The domain name is sent to HIBP:
``EXTERNAL_DOMAIN_LOOKUPS`` can switch this off. Nothing is sent to the assessed domain.

Only facts are kept: when it happened, how many accounts, what kind of data, and HIBP's own
flags (verified, fabricated, spam list, malware, ...). HIBP's descriptions are HTML written by
a third party and are never stored.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.checks.base import CheckContext, CheckOutcome, CheckScope, lookup_enabled
from app.service.discovery.psl import registrable_domain
from app.service.ratelimit import LIMITERS

URL = "https://haveibeenpwned.com/api/v3/breaches"
CACHE_FOR = timedelta(hours=24)
MAX_BREACHES = 20
MAX_CLASSES = 12
RATE_PER_SECOND = 0.5  # one request per two seconds, shared by all worker threads


def _text(value: object, limit: int = 100) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return "".join(ch for ch in value if ch.isprintable())[:limit] or None


def _date(value: object) -> str | None:
    """A ``YYYY-MM-DD`` (or full ISO) date as a normalised date string, else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def _flag(item: dict[str, Any], name: str) -> bool:
    return item.get(name) is True


def parse_breach(item: object) -> dict[str, Any] | None:
    """One breach as plain, bounded data; ``None`` for an entry that is not a breach."""
    if not isinstance(item, dict) or not _text(item.get("Name")):
        return None
    count = item.get("PwnCount")
    classes = item.get("DataClasses")
    return {
        "name": _text(item.get("Name")),
        "title": _text(item.get("Title")),
        "domain": _text(item.get("Domain"), 253),
        "breach_date": _date(item.get("BreachDate")),
        "added_date": _date(item.get("AddedDate")),
        "pwn_count": count if isinstance(count, int) and not isinstance(count, bool) else None,
        "data_classes": [c for c in (_text(x, 60) for x in classes[: MAX_CLASSES * 2]) if c][
            :MAX_CLASSES
        ]
        if isinstance(classes, list)
        else [],
        "verified": _flag(item, "IsVerified"),
        "fabricated": _flag(item, "IsFabricated"),
        "sensitive": _flag(item, "IsSensitive"),
        "retired": _flag(item, "IsRetired"),
        "spam_list": _flag(item, "IsSpamList"),
        "malware": _flag(item, "IsMalware"),
        "stealer_log": _flag(item, "IsStealerLog"),
    }


class BreachesCheck:
    """Ask Have I Been Pwned for the public breaches of the domain."""

    key = "breaches"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = registrable_domain(ctx.domain) or ctx.domain.lower().rstrip(".")
        if not lookup_enabled(ctx.config, "hibp"):
            return CheckOutcome("unavailable", "disabled", {"domain": domain})
        base = {"domain": ctx.domain, "queried": domain}
        if ctx.cache is not None:
            hit = ctx.cache.get("hibp", domain, CACHE_FOR)
            if hit is not None and hit.status in ("ok", "no_data"):
                data = {
                    **base,
                    **hit.payload,
                    "cached": True,
                    "fetched_at": hit.fetched_at.isoformat(),
                }
                return _outcome(hit.status == "ok", data)
        LIMITERS.get("hibp", RATE_PER_SECOND).acquire()
        try:
            response = ctx.http.get(URL, params={"domain": domain})
        except httpx.TimeoutException:
            return CheckOutcome("error", "timeout", base, "hibp")
        except httpx.HTTPError:
            return CheckOutcome("error", "connection_failed", base, "hibp")
        code = response.status_code
        if code == 429:
            return CheckOutcome("unavailable", "rate_limited", base, "hibp")
        if code != 200:
            return CheckOutcome("error", f"http_{code}", base, "hibp")
        try:
            body: Any = response.json()
        except ValueError:
            body = None
        if not isinstance(body, list):
            return CheckOutcome("error", "invalid_response", base, "hibp")
        breaches = [b for b in (parse_breach(item) for item in body[:200]) if b is not None]
        breaches.sort(key=lambda b: (b["breach_date"] or "", b["name"] or ""), reverse=True)
        facts = {
            "total": len(breaches),
            "latest_breach_date": next(
                (b["breach_date"] for b in breaches if b["breach_date"]), None
            ),
            "breaches": breaches[:MAX_BREACHES],
        }
        if ctx.cache is not None:
            ctx.cache.put("hibp", domain, "ok" if breaches else "no_data", facts)
        data = {**base, **facts, "cached": False, "fetched_at": datetime.now(UTC).isoformat()}
        return _outcome(bool(breaches), data)


def _outcome(found: bool, data: dict[str, Any]) -> CheckOutcome:
    """Breaches found is ``ok``; none known is ``no_data`` (asked, nothing there), never "clean"."""
    if found:
        return CheckOutcome("ok", None, data, "hibp")
    return CheckOutcome("no_data", "no_breach_known", data, "hibp")
