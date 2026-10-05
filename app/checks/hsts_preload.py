"""HSTS preload status of the domain, from hstspreload.org (the list browsers ship).

A domain-level check that asks hstspreload.org's public API which state the domain is in:
``preloaded`` (browsers force HTTPS for it), ``pending`` (accepted, not yet shipped), ``rejected``,
``removed`` or ``unknown`` (not on the list). The domain name is sent to hstspreload.org:
``EXTERNAL_DOMAIN_LOOKUPS`` can switch this off. Nothing is sent to the assessed domain.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.checks.base import CheckContext, CheckOutcome, CheckScope, lookup_enabled

URL = "https://hstspreload.org/api/v2/status?domain={domain}"
STATES = ("preloaded", "pending", "rejected", "removed", "unknown")
CACHE_FOR = timedelta(hours=24)


class HstsPreloadCheck:
    """Ask hstspreload.org whether the domain is on the preload list."""

    key = "hsts_preload"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = ctx.domain.lower().rstrip(".")
        if not lookup_enabled(ctx.config, "hsts_preload"):
            return CheckOutcome("unavailable", "disabled", {"domain": domain})
        if ctx.cache is not None:
            hit = ctx.cache.get("hstspreload", domain, CACHE_FOR)
            if hit is not None and hit.status == "ok":
                data = {**hit.payload, "cached": True, "fetched_at": hit.fetched_at.isoformat()}
                return CheckOutcome("ok", data=data, source="hstspreload.org")
        try:
            response = ctx.http.get(URL.format(domain=quote(domain, safe="")))
        except httpx.TimeoutException:
            return CheckOutcome("error", "timeout", {"domain": domain}, "hstspreload.org")
        except httpx.HTTPError:  # no exception text: it can hold the URL
            return CheckOutcome("error", "connection_failed", {"domain": domain}, "hstspreload.org")
        code = response.status_code
        if code == 429:
            return CheckOutcome(
                "unavailable", "rate_limited", {"domain": domain}, "hstspreload.org"
            )
        if code != 200:
            return CheckOutcome("error", f"http_{code}", {"domain": domain}, "hstspreload.org")
        try:
            body: Any = response.json()
        except ValueError:
            body = None
        state = body.get("status") if isinstance(body, dict) else None
        if state not in STATES:
            return CheckOutcome("error", "invalid_response", {"domain": domain}, "hstspreload.org")
        covered = body.get("preloadedDomain")
        facts = {
            "domain": domain,
            "status": state,
            "preloaded": state == "preloaded",
            "preloaded_domain": covered[:253] if isinstance(covered, str) and covered else None,
        }
        if ctx.cache is not None:
            ctx.cache.put("hstspreload", domain, "ok", facts)
        data = {**facts, "cached": False, "fetched_at": datetime.now(UTC).isoformat()}
        return CheckOutcome("ok", data=data, source="hstspreload.org")
