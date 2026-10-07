"""Subdomain takeover: is an alias for a hosted service pointing at a resource nobody has claimed?

Needs the DNS check. When the host is an alias (CNAME) for a service in ``takeover_services``,
the check looks at the one thing that decides whether a stranger could take the name over:

- for a service that lets anyone register a name that does not exist (``dns``), the DNS check's
  answer is enough: the alias ends in a name that does not exist;
- for a service that answers an unknown host with a page of its own (``page``), the host is asked
  for its home page, over plain HTTP first, through the egress gate (screened addresses, IP-pinned,
  verified certificates, 64 KB, three redirects at most), and the answer is compared with what the
  service shows for an unclaimed name (status and text).

Nothing is claimed, registered or changed anywhere: it is the request any visitor would send. A host
that is not an alias for one of the listed services costs no request at all. The page itself is
never stored, only which known signature it showed. A page that cannot be read (a service that
redirects to HTTPS with a certificate for another name; certificate verification is never turned
off) is reported as *not tested* with the reason, never as "in use".
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.fetch import (
    ClientFactory,
    Document,
    NameResolver,
    default_client,
    default_names,
    fetch_document,
)
from app.checks.takeover_services import (
    CHECKED_ON,
    SOURCE,
    Service,
    normalise,
    services_for,
)

MAX_ALIASES = 8  # CNAME steps kept in the result
MAX_CANDIDATES = 3  # services tested per host; a longer chain is not a real setup
BUDGET_SECONDS = 45.0
REQUEST_HEADERS = {"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"}
# Errors after which asking the same host over HTTPS cannot help.
FINAL_ERRORS = frozenset({"tls_verification_failed", "blocked_destination", "dns_failed"})


@dataclass
class Observation:
    """What one request for the home page came back with (the text is kept only to compare)."""

    url: str
    status: int | None
    text: str  # normalised, never stored
    error: str | None


def _observation(document: Document) -> Observation:
    response = document.response
    if response is None:
        return Observation(document.url, None, "", document.error or "no_response")
    return Observation(response.url, response.status_code, normalise(response.text), None)


def _candidate(service: Service, target: str) -> dict[str, Any]:
    return {
        "service": service.key,
        "name": service.name,
        "target": target[:253],
        "how": service.how,
        "claim": service.claim,
        "verdict": None,  # claimable | unclaimed | in_use | not_tested
        "status": None,
        "url": None,
        "signature": None,
        "error": None,
    }


def _judge_dns(candidate: dict[str, Any], service: Service, dns: Mapping[str, Any]) -> None:
    canonical = str(dns.get("canonical_name", ""))
    dangling = bool(dns.get("dangling_cname")) and service.matches(canonical)
    candidate["verdict"] = "claimable" if dangling else "in_use"


def _judge_page(
    candidate: dict[str, Any], service: Service, observations: list[Observation]
) -> None:
    for seen in observations:
        if seen.status not in service.statuses:
            continue
        for signature in service.signatures:
            if normalise(signature) in seen.text:
                candidate.update(
                    verdict="unclaimed", status=seen.status, url=seen.url, signature=signature
                )
                return
    answered = [seen for seen in observations if seen.status is not None]
    if answered:
        last = answered[-1]
        candidate.update(verdict="in_use", status=last.status, url=last.url)
        return
    candidate.update(
        verdict="not_tested",
        error=next((seen.error for seen in observations if seen.error), "no_response"),
    )


class TakeoverCheck:
    """Find aliases for hosted services whose name behind the alias nobody has claimed."""

    key = "takeover"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        name_resolver: NameResolver | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_factory = client_factory or default_client
        self._names = name_resolver or default_names
        self._monotonic = monotonic

    def run(self, ctx: CheckContext) -> CheckOutcome:
        dns = ctx.previous.get("dns")
        dns_data: Mapping[str, Any] = dns.data if dns else {}
        host = (ctx.hostname or "").lower().rstrip(".")
        steps = [step for step in dns_data.get("cname", []) if isinstance(step, Mapping)]
        data: dict[str, Any] = {
            "aliases": [
                {
                    "name": str(step.get("name", ""))[:253],
                    "target": str(step.get("target", ""))[:253],
                }
                for step in steps[:MAX_ALIASES]
            ],
            "candidates": [],
            "candidates_cut": 0,  # services beyond MAX_CANDIDATES that were not looked at
            "fingerprints": CHECKED_ON,
        }

        found: list[tuple[Service, str]] = []
        for step in steps:
            target = str(step.get("target", "")).lower().rstrip(".")
            for service in services_for(target):
                if all(service.key != known.key for known, _ in found):
                    found.append((service, target))
        if not found:
            return CheckOutcome("ok", data=data, source=SOURCE)

        chosen = found[:MAX_CANDIDATES]
        candidates = [_candidate(service, target) for service, target in chosen]
        data["candidates"] = candidates
        data["candidates_cut"] = len(found) - len(chosen)
        deadline = self._monotonic() + BUDGET_SECONDS
        observations: list[Observation] | None = None
        for candidate, (service, _target) in zip(candidates, chosen, strict=True):
            if service.how == "dns":
                _judge_dns(candidate, service, dns_data)
                continue
            addresses = [str(ip) for ip in dns_data.get("addresses", [])]
            if not addresses:
                candidate.update(verdict="not_tested", error="no_public_address")
                continue
            if observations is None:
                if self._monotonic() > deadline:
                    candidate.update(verdict="not_tested", error="budget_exceeded")
                    continue
                observations = self._observe(ctx, host, addresses, deadline)
            _judge_page(candidate, service, observations)

        if all(candidate["verdict"] == "not_tested" for candidate in candidates):
            reason = str(candidates[0]["error"] or "no_response")
            if reason == "no_public_address":
                return CheckOutcome("skipped", reason, data, SOURCE)
            return CheckOutcome("error", reason, data, SOURCE)
        return CheckOutcome("ok", data=data, source=SOURCE)

    def _observe(
        self, ctx: CheckContext, host: str, addresses: list[str], deadline: float
    ) -> list[Observation]:
        """Ask the host for its home page: plain HTTP first, HTTPS only if that got no answer."""

        def resolve(name: str) -> list[str]:
            # The host itself uses the addresses DNS already screened; the names a redirect leads
            # to are looked up the same way and then screened again by the gate.
            name = name.lower().rstrip(".")
            return list(addresses) if name == host else self._names(ctx.config, name)

        client = self._client_factory(ctx.config, resolve)
        headers = {
            **REQUEST_HEADERS,
            "User-Agent": str(ctx.config.get("USER_AGENT", "WebDueDiligence")),
        }
        observations: list[Observation] = []
        for url in (f"http://{host}/", f"https://{host}/"):
            if observations and self._monotonic() > deadline:
                observations.append(Observation(url, None, "", "budget_exceeded"))
                break
            seen = _observation(fetch_document(client, url, headers))
            observations.append(seen)
            if seen.status is not None or seen.error in FINAL_ERRORS:
                break
        return observations
