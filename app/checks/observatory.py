"""Mozilla's HTTP Observatory: an independent grade of the home page's security headers.

Opt-in: ``EXTERNAL_DOMAIN_LOOKUPS`` must name ``observatory``, because of what it does. The domain
name is sent to Mozilla, whose scanner then requests the home page and a few well-known files from
the domain's own servers, and the scan and its grade are public on MDN: there is no way to hide a
scan. Nothing is sent to the assessed domain from here.

This is a second opinion, not a finding. The grade is Mozilla's; it can differ from what our own
rules say about the same headers because the two look from different places with different tests.
The API's answer is untrusted input: every field is checked and bounded, and a link to the details
is kept only if it points to MDN.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.checks.base import CheckContext, CheckOutcome, CheckScope, lookup_enabled
from app.service.discovery.psl import registrable_domain

URL = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
DETAILS_PREFIX = "https://developer.mozilla.org/"  # a details link must start like this
SOURCE = "mdn-observatory"
CACHE_PROVIDER = "observatory"
CACHE_FOR = timedelta(hours=24)  # Mozilla lets a site be scanned once a minute: do not ask again
GRADE = re.compile(r"[A-F][+-]?")
MAX_SCORE_SEEN = 400  # the scale ends at 145; anything wildly above is not a score
MAX_COUNT = 1000
# Answers of the API that say the *name* cannot be scanned, whatever host is tried: no use asking
# for ``www.`` as well.
NOT_A_SITE = frozenset({"invalid-site", "invalid-hostname-ip"})


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNT:
        return None
    return value


def facts_of(body: Any) -> dict[str, Any] | None:
    """The bounded facts of a scan answer, or ``None`` when it is not one."""
    if not isinstance(body, dict):
        return None
    grade, score = body.get("grade"), body.get("score")
    if not isinstance(grade, str) or not GRADE.fullmatch(grade):
        return None
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= MAX_SCORE_SEEN:
        return None
    counts = [_count(body.get(key)) for key in ("tests_passed", "tests_failed", "tests_quantity")]
    if any(count is None for count in counts):
        return None
    details = body.get("details_url")
    scanned = body.get("scanned_at")
    status = body.get("status_code")
    version = body.get("algorithm_version")
    return {
        "grade": grade,
        "score": score,
        "tests_passed": counts[0],
        "tests_failed": counts[1],
        "tests_quantity": counts[2],
        "status_code": status if isinstance(status, int) and not isinstance(status, bool) else None,
        "scanned_at": scanned[:40] if isinstance(scanned, str) else None,
        "algorithm_version": version if isinstance(version, int) else None,
        "details_url": details[:300]
        if isinstance(details, str) and details.startswith(DETAILS_PREFIX)
        else None,
    }


def _problem_code(body: Any) -> str:
    """The API's own name for what went wrong, as a reason code (``scan-failed`` → a code)."""
    code = body.get("error") if isinstance(body, dict) else None
    if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,40}", code):
        return code.replace("-", "_")
    return "not_scannable"


class ObservatoryCheck:
    """Ask Mozilla's HTTP Observatory for its grade of the domain's home page."""

    key = "observatory"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = ctx.domain.lower().rstrip(".")
        if not lookup_enabled(ctx.config, "observatory"):
            return CheckOutcome("skipped", "disabled", {"domain": domain})
        hosts = [domain]
        if registrable_domain(domain) == domain:  # the site is often only at www.
            hosts.append(f"www.{domain}")
        tried: list[str] = []
        outcome = CheckOutcome("no_data", "not_scannable", {"domain": domain})
        for host in hosts:
            tried.append(host)
            outcome = self._scan(ctx, domain, host)
            if outcome.status == "ok" or not self._worth_another_host(outcome):
                break
        return CheckOutcome(
            outcome.status, outcome.reason_code, {**outcome.data, "tried": tried}, outcome.source
        )

    @staticmethod
    def _worth_another_host(outcome: CheckOutcome) -> bool:
        """Only a host that could not be scanned may be answered for by its ``www.`` sibling."""
        return outcome.status == "no_data" and outcome.data.get("api_error") not in NOT_A_SITE

    def _scan(self, ctx: CheckContext, domain: str, host: str) -> CheckOutcome:
        base = {"domain": domain, "host": host}
        if ctx.cache is not None:
            hit = ctx.cache.get(CACHE_PROVIDER, host, CACHE_FOR)
            if hit is not None and hit.status == "ok":
                data = {
                    **base,
                    **hit.payload,
                    "cached": True,
                    "fetched_at": hit.fetched_at.isoformat(),
                }
                return CheckOutcome("ok", data=data, source=SOURCE)
        try:
            response = ctx.http.post(URL, params={"host": host})
        except httpx.TimeoutException:
            return CheckOutcome("error", "timeout", base, SOURCE)
        except httpx.HTTPError:  # no exception text: it can hold the URL
            return CheckOutcome("error", "connection_failed", base, SOURCE)
        code = response.status_code
        try:
            body: Any = response.json()
        except ValueError:
            body = None
        if code == 429:
            return CheckOutcome("unavailable", "rate_limited", base, SOURCE)
        if code == 422:
            reason = _problem_code(body)
            return CheckOutcome(
                "no_data", reason, {**base, "api_error": reason.replace("_", "-")}, SOURCE
            )
        if code != 200:
            return CheckOutcome("error", f"http_{code}", base, SOURCE)
        if isinstance(body, dict) and body.get("error"):
            reason = _problem_code(body)
            return CheckOutcome(
                "no_data", reason, {**base, "api_error": reason.replace("_", "-")}, SOURCE
            )
        facts = facts_of(body)
        if facts is None:
            return CheckOutcome("error", "invalid_response", base, SOURCE)
        if ctx.cache is not None:
            ctx.cache.put(CACHE_PROVIDER, host, "ok", facts)
        data = {**base, **facts, "cached": False, "fetched_at": datetime.now(UTC).isoformat()}
        return CheckOutcome("ok", data=data, source=SOURCE)
