"""Registration: registrar, creation and expiry dates, status locks, name servers and DNSSEC.

The facts come from the domain's registry over RDAP (RFC 9083).

A domain-level check. The registry is found through IANA's bootstrap file (cached for a day); a few
ccTLD registries that run RDAP although IANA does not list them are added from ``SUPPLEMENTAL``.
Both requests go through the egress gate. The domain name is sent to the registry: switch the
lookup off with ``EXTERNAL_DOMAIN_LOOKUPS``.

Only facts about the *registration* are kept. Registrant and contact entities, which some
registries publish, are deliberately dropped: they describe people, and nothing here needs them.
What a registry does not publish stays ``None`` (``.ch`` and ``.de`` give no dates), never a guess.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from app.checks.base import CheckContext, CheckOutcome, CheckScope, lookup_enabled
from app.checks.fetch import (
    ClientFactory,
    NameResolver,
    default_client,
    default_names,
    fetch_document,
)
from app.service.discovery.psl import registrable_domain

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_BOOTSTRAP_BYTES = 512 * 1024
MAX_RDAP_BYTES = 128 * 1024
CACHE_FOR = timedelta(hours=24)
MAX_TLDS = 5000
MAX_LIST = 20
# RDAP servers of ccTLD registries that are missing from IANA's bootstrap file (checked 2026-10-05).
SUPPLEMENTAL = {
    "ch": "https://rdap.nic.ch/",
    "li": "https://rdap.nic.ch/",
    "de": "https://rdap.denic.de/",
    "io": "https://rdap.identitydigital.services/rdap/",
}
TRANSFER_LOCKS = ("client transfer prohibited", "server transfer prohibited")


def parse_bootstrap(raw: object) -> dict[str, str]:
    """TLD -> RDAP base URL from IANA's ``dns.json``. Only ``https`` URLs are accepted."""
    services: dict[str, str] = {}
    entries = raw.get("services") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        return services
    for entry in entries:
        if not (isinstance(entry, list) and len(entry) == 2):
            continue
        tlds, urls = entry
        if not (isinstance(tlds, list) and isinstance(urls, list)):
            continue
        base = next((u for u in urls if isinstance(u, str) and u.startswith("https://")), None)
        if base is None:
            continue
        for tld in tlds:
            if isinstance(tld, str) and len(services) < MAX_TLDS:
                services[tld.strip().lower()] = base if base.endswith("/") else base + "/"
    return services


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(value: object, limit: int = 200) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return "".join(ch for ch in value if ch.isprintable())[:limit] or None


def _vcard_name(card: object) -> str | None:
    """The ``fn`` (else the ``org``) of a jCard; its address, phone and e-mail are never read."""
    fn = org = None
    items = card[1] if isinstance(card, list) and len(card) > 1 else []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, list) and len(item) >= 4 and isinstance(item[3], str):
            if item[0] == "fn":
                fn = _text(item[3])
            elif item[0] == "org":
                org = _text(item[3])
    return fn or org


def _registrar(entities: object) -> dict[str, str | None] | None:
    """Name and IANA id of the registrar entity; no other entity is read."""
    for entity in entities if isinstance(entities, list) else []:
        roles = entity.get("roles") if isinstance(entity, dict) else None
        if not (isinstance(roles, list) and "registrar" in roles):
            continue
        iana_id = next(
            (
                _text(pid.get("identifier"), 20)
                for pid in entity.get("publicIds") or []
                if isinstance(pid, dict) and pid.get("type") == "IANA Registrar ID"
            ),
            None,
        )
        return {"name": _vcard_name(entity.get("vcardArray")), "iana_id": iana_id}
    return None


def parse_rdap(body: Mapping[str, Any]) -> dict[str, Any]:
    """The registration facts of an RDAP ``domain`` object (dates as ISO strings in UTC)."""
    events: dict[str, datetime] = {}
    for event in body.get("events") or []:
        if isinstance(event, dict) and isinstance(event.get("eventAction"), str):
            when = _date(event.get("eventDate"))
            if when is not None:
                events.setdefault(event["eventAction"].strip().lower(), when)
    statuses = sorted(
        {s.strip().lower() for s in body.get("status") or [] if isinstance(s, str) and s.strip()}
    )[:MAX_LIST]
    names = sorted(
        {
            n["ldhName"].strip().lower().rstrip(".")
            for n in body.get("nameservers") or []
            if isinstance(n, dict) and isinstance(n.get("ldhName"), str) and n["ldhName"].strip()
        }
    )[:MAX_LIST]
    secure = body.get("secureDNS")
    dnssec: bool | None = None
    if isinstance(secure, dict):
        if secure.get("delegationSigned") is True or secure.get("dsData") or secure.get("keyData"):
            dnssec = True
        elif secure.get("delegationSigned") is False:
            dnssec = False

    def iso(action: str) -> str | None:
        return events[action].astimezone(UTC).isoformat() if action in events else None

    return {
        "registrar": _registrar(body.get("entities")),
        "created": iso("registration"),
        "expires": iso("expiration"),
        "changed": iso("last changed"),
        "statuses": statuses,
        "transfer_locked": any(lock in statuses for lock in TRANSFER_LOCKS),
        "nameservers": names,
        "dnssec": dnssec,
    }


def with_ages(facts: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """``facts`` plus the days to expiry and the age, worked out at ``now`` (never stored)."""
    result = dict(facts)
    expires, created = _date(facts.get("expires")), _date(facts.get("created"))
    result["days_to_expiry"] = (expires - now).days if expires else None
    result["age_days"] = (now - created).days if created else None
    result["dates_published"] = bool(expires or created)
    return result


class RegistrationCheck:
    """Ask the registry of the domain (RDAP) about its registration."""

    key = "registration"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        name_resolver: NameResolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client_factory = client_factory or default_client
        self._names = name_resolver or default_names
        self._clock = clock or (lambda: datetime.now(UTC))

    def run(self, ctx: CheckContext) -> CheckOutcome:
        if not lookup_enabled(ctx.config, "rdap"):
            return CheckOutcome("skipped", "disabled", {"domain": ctx.domain})
        domain = registrable_domain(ctx.domain)
        if domain is None:
            return CheckOutcome("no_data", "not_registrable", {"domain": ctx.domain})
        now = self._clock()
        if ctx.cache is not None:
            hit = ctx.cache.get("rdap", domain, CACHE_FOR)
            if hit is not None and hit.status == "ok":
                data = {**with_ages(hit.payload, now), "cached": True}
                data["fetched_at"] = hit.fetched_at.isoformat()
                return CheckOutcome("ok", data=data, source=_source(hit.payload.get("server")))

        def resolve(name: str) -> list[str]:
            return self._names(ctx.config, name)

        base, error = self._server(ctx, domain.rsplit(".", 1)[-1], resolve)
        if base is None:
            return CheckOutcome(
                "no_data" if error == "no_rdap_service" else "error",
                error,
                {"domain": ctx.domain, "queried": domain},
            )
        client = self._client_factory(ctx.config, resolve)
        client.max_response_bytes = MAX_RDAP_BYTES
        document = fetch_document(
            client, f"{base}domain/{domain}", {"Accept": "application/rdap+json, application/json"}
        )
        base_data = {"domain": ctx.domain, "queried": domain, "server": base}
        source = _source(base)
        response = document.response
        if response is None:
            return CheckOutcome("error", document.error, base_data, source)
        code = response.status_code
        if code == 404:
            return CheckOutcome("no_data", "not_found", base_data, source)
        if code == 429:
            return CheckOutcome("unavailable", "rate_limited", base_data, source)
        if code in (401, 403):
            return CheckOutcome("unavailable", "not_allowed", base_data, source)
        if code != 200:
            return CheckOutcome("error", f"http_{code}", base_data, source)
        try:
            body = json.loads(response.text)
        except ValueError:
            body = None
        if not isinstance(body, dict) or body.get("objectClassName") != "domain":
            return CheckOutcome("error", "invalid_response", base_data, source)
        facts = {**base_data, **parse_rdap(body)}
        if ctx.cache is not None:
            ctx.cache.put("rdap", domain, "ok", facts)
        data = {**with_ages(facts, now), "cached": False, "fetched_at": now.isoformat()}
        return CheckOutcome("ok", data=data, source=source)

    def _server(
        self, ctx: CheckContext, tld: str, resolve: Callable[[str], list[str]]
    ) -> tuple[str | None, str | None]:
        """The registry's RDAP base URL, or the reason there is none."""
        services = self._bootstrap(ctx, resolve)
        if services is not None and tld in services:
            return services[tld], None
        if tld in SUPPLEMENTAL:
            return SUPPLEMENTAL[tld], None
        if services is None:
            return None, "bootstrap_failed"
        return None, "no_rdap_service"

    def _bootstrap(
        self, ctx: CheckContext, resolve: Callable[[str], list[str]]
    ) -> dict[str, str] | None:
        if ctx.cache is not None:
            hit = ctx.cache.get("iana-rdap", "dns.json", CACHE_FOR)
            if (
                hit is not None
                and hit.status == "ok"
                and isinstance(hit.payload.get("services"), dict)
            ):
                return {str(k): str(v) for k, v in hit.payload["services"].items()}
        client = self._client_factory(ctx.config, resolve)
        client.max_response_bytes = MAX_BOOTSTRAP_BYTES
        document = fetch_document(client, BOOTSTRAP_URL, {"Accept": "application/json"})
        response = document.response
        if response is None or response.status_code != 200 or response.truncated:
            return None
        try:
            services = parse_bootstrap(json.loads(response.text))
        except ValueError:
            return None
        if not services:
            return None
        if ctx.cache is not None:
            ctx.cache.put("iana-rdap", "dns.json", "ok", {"services": services})
        return services


def _source(base: object) -> str | None:
    host = urlsplit(str(base)).hostname if base else None
    return f"rdap:{host}"[:64] if host else None
