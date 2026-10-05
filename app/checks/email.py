"""Email security of the assessed domain: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI.

A domain-level check (it runs once per scan, for the domain itself). Everything is read from DNS
through the configured resolvers; only the MTA-STS policy is fetched over HTTPS, through the egress
gate. Each part states what was *found*; judging it (a missing DMARC record, ``p=none``) is the job
of the rules. A part that could not be asked says why (``error``), it is never reported as absent.

DKIM cannot be enumerated: a selector is only found by guessing its name, so "no selector found"
means exactly that and nothing more.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.dns import SHARED_RESOLVERS, Lookup, ResolverCache, ResolverLike, lookup_records
from app.checks.fetch import (
    ClientFactory,
    NameResolver,
    default_client,
    default_names,
    fetch_document,
)

BUDGET_SECONDS = 40.0  # all DNS lookups of one run; what is left unasked is reported as an error
MAX_SPF_FETCHES = 10  # DNS lookups spent following include / redirect
MAX_SPF_TERMS = 60
MAX_LIST = 20
MAX_URI = 200
STOP_AFTER = ("timeout", "network_error", "servfail")  # resolver trouble: stop asking the rest

# Names worth trying for DKIM: the defaults of the common mail platforms. Not exhaustive by nature.
DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
    "email",
    "key1",
    "key2",
    "mandrill",
    "mxvault",
    "zoho",
    "zmail",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
)

# Hosts that receive mail for many domains: who handles this domain's mail.
MAIL_PROVIDERS = (
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("messagelabs.com", "Broadcom (Symantec) Email Security"),
    ("protonmail.ch", "Proton Mail"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("mailgun.org", "Mailgun"),
    ("secureserver.net", "GoDaddy"),
    ("ionos.com", "IONOS"),
    ("infomaniak.ch", "Infomaniak"),
    ("hostpoint.ch", "Hostpoint"),
    ("cyon.ch", "cyon"),
    ("fastmail.com", "Fastmail"),
    ("messagingengine.com", "Fastmail"),
    ("yandex.net", "Yandex"),
    ("mailanyone.net", "Mailanyone"),
)
# Names in an SPF record that stand for a service allowed to send in the domain's name.
SENDER_SERVICES = (
    ("_spf.google.com", "Google Workspace"),
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("amazonses.com", "Amazon SES"),
    ("mandrillapp.com", "Mandrill (Mailchimp)"),
    ("servers.mcsv.net", "Mailchimp"),
    ("spf.mtasv.net", "Postmark"),
    ("salesforce.com", "Salesforce"),
    ("mktomail.com", "Marketo"),
    ("zendesk.com", "Zendesk"),
    ("sendinblue.com", "Brevo"),
    ("brevo.com", "Brevo"),
    ("mailjet.com", "Mailjet"),
    ("createsend.com", "Campaign Monitor"),
    ("hubspotemail.net", "HubSpot"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("protection.outlook.com", "Microsoft 365"),
    ("zoho.com", "Zoho"),
)

_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
_COUNTED = frozenset({"include", "a", "mx", "ptr", "exists"})  # RFC 7208 4.6.4
_MODIFIER = re.compile(r"^([a-z][a-z0-9._-]*)=(.*)$")
_MECHANISM = re.compile(r"^([+\-~?])?([a-z0-9]+)(.*)$")
_DMARC_POLICIES = ("none", "quarantine", "reject")


# ------------------------------------------------------------------------------ parsing


def parse_tags(text: str) -> dict[str, str]:
    """``k=v; k=v`` records (DMARC, DKIM, TLS-RPT, BIMI, MTA-STS ids): keys lower-cased, the first
    occurrence of a key wins, values trimmed."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        key, separator, value = part.partition("=")
        key = key.strip().lower()
        if separator and key and key not in tags:
            tags[key] = value.strip()
    return tags


def _service(name: str, table: tuple[tuple[str, str], ...]) -> str | None:
    cleaned = name.strip().lower().rstrip(".")
    for suffix, service in table:
        if cleaned == suffix or cleaned.endswith("." + suffix):
            return service
    return None


def mail_provider(host: str) -> str | None:
    """The mail platform an MX host belongs to (``None`` for a host we do not know)."""
    return _service(host, MAIL_PROVIDERS)


def is_spf(text: str) -> bool:
    return text.strip().lower().split(None, 1)[:1] == ["v=spf1"]


def parse_spf(text: str) -> dict[str, Any]:
    """One SPF record as plain data: its terms, the final ``all``, include / redirect targets and
    the lookups this record alone spends (RFC 7208 4.6.4)."""
    terms: list[dict[str, str]] = []
    includes: list[str] = []
    problems: list[str] = []
    redirect: str | None = None
    final_all: str | None = None
    lookups = 0
    for token in text.strip().split()[1 : MAX_SPF_TERMS + 1]:
        lowered = token.lower()
        modifier = _MODIFIER.match(lowered)
        if modifier:
            name, value = modifier.groups()
            if name == "redirect" and redirect is None:
                redirect, lookups = value.rstrip(".")[:253], lookups + 1
            elif name not in ("redirect", "exp"):
                problems.append("unknown_modifier")
            continue
        match = _MECHANISM.match(lowered)
        if match is None:
            problems.append("unknown_term")
            continue
        qualifier = match.group(1) or "+"
        name, rest = match.group(2), match.group(3)
        if name not in _MECHANISMS:
            problems.append("unknown_term")
            continue
        value = rest[1:] if rest[:1] == ":" else rest  # "a/24" keeps its "/24"
        terms.append({"q": qualifier, "mechanism": name, "value": value[:253]})
        if name == "all" and final_all is None:
            final_all = _QUALIFIERS[qualifier]
        if name == "include" and value:
            includes.append(value.rstrip(".")[:253])
        if name == "ptr":
            problems.append("ptr_used")
        if name in _COUNTED:
            lookups += 1
    return {
        "terms": terms,
        "all": final_all,
        "includes": includes[:MAX_LIST],
        "redirect": redirect,
        "direct_lookups": lookups,
        "problems": sorted(set(problems)),
    }


def parse_dmarc(text: str) -> dict[str, Any]:
    tags = parse_tags(text)
    problems: list[str] = []
    policy = tags.get("p", "").lower() or None
    if policy not in _DMARC_POLICIES:
        problems.append("invalid_policy")
        policy = None
    subdomain = tags.get("sp", "").lower() or None
    if subdomain is not None and subdomain not in _DMARC_POLICIES:
        problems.append("invalid_subdomain_policy")
        subdomain = None
    pct: int | None = 100
    if "pct" in tags:
        pct = int(tags["pct"]) if re.fullmatch(r"\d{1,3}", tags["pct"]) else None
        if pct is None or pct > 100:
            problems.append("invalid_pct")
            pct = None
    return {
        "policy": policy,
        "subdomain_policy": subdomain,
        "pct": pct,
        "rua": _uris(tags.get("rua", "")),
        "ruf": _uris(tags.get("ruf", "")),
        "adkim": (tags.get("adkim", "r") or "r").lower()[:1],
        "aspf": (tags.get("aspf", "r") or "r").lower()[:1],
        "problems": problems,
    }


def _uris(value: str) -> list[str]:
    parts = [part.strip()[:MAX_URI] for part in value.split(",") if part.strip()]
    return parts[:MAX_LIST]


def dkim_key(text: str) -> dict[str, Any]:
    """What a DKIM key record says about the key: type, size, revoked, testing."""
    tags = parse_tags(text)
    key_type = (tags.get("k", "rsa") or "rsa").lower()[:10]
    material = re.sub(r"\s+", "", tags.get("p", ""))
    bits: int | None = None
    if material:
        try:
            key = load_der_public_key(base64.b64decode(material, validate=False))
        except (ValueError, binascii.Error, UnsupportedAlgorithm):
            key = None
        if isinstance(key, rsa.RSAPublicKey):
            bits = key.key_size
        elif isinstance(key, ed25519.Ed25519PublicKey):
            bits = 256
    flags = {flag.strip().lower() for flag in tags.get("t", "").split(":")}
    return {"key_type": key_type, "bits": bits, "revoked": not material, "testing": "y" in flags}


def parse_mta_sts_policy(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines()[:100]:
        key, separator, value = line.partition(":")
        if separator:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    max_age = fields.get("max_age", [""])[0]
    mode = fields.get("mode", [""])[0].lower()
    return {
        "valid": fields.get("version", [""])[0] == "STSv1"
        and mode in ("enforce", "testing", "none"),
        "mode": mode or None,
        "mx": [name[:MAX_URI] for name in fields.get("mx", [])][:MAX_LIST],
        "max_age": int(max_age) if re.fullmatch(r"\d{1,10}", max_age) else None,
    }


# ------------------------------------------------------------------------------ the check


class _Budget:
    def __init__(self, seconds: float, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._deadline = clock() + seconds

    @property
    def spent(self) -> bool:
        return self._clock() > self._deadline


class EmailCheck:
    """Read the mail-related DNS records of the domain, and its MTA-STS policy."""

    key = "email"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def __init__(
        self,
        resolver_factory: Callable[[Mapping[str, Any]], ResolverLike] | None = None,
        client_factory: ClientFactory | None = None,
        name_resolver: NameResolver | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolvers = (
            SHARED_RESOLVERS if resolver_factory is None else ResolverCache(resolver_factory)
        )
        self._client_factory = client_factory or default_client
        self._names = name_resolver or default_names
        self._clock = clock

    def run(self, ctx: CheckContext) -> CheckOutcome:
        domain = ctx.domain.lower().rstrip(".")
        resolver = self._resolvers.get(ctx.config)
        lifetime = float(ctx.config.get("DNS_TIMEOUT_SECONDS", 5.0))
        servers = [str(server) for server in ctx.config.get("EGRESS_DNS_RESOLVERS", [])]
        source = ("dns:" + (",".join(servers) if servers else "system"))[:64]
        budget = _Budget(BUDGET_SECONDS, self._clock)

        mx = lookup_records(resolver, domain, "MX", lifetime)
        if mx.nxdomain:
            return CheckOutcome("no_data", "nxdomain", {"domain": domain}, source)
        txt = lookup_records(resolver, domain, "TXT", lifetime)
        if mx.error and txt.error:  # two failures in a row: do not spend a timeout on every part
            return CheckOutcome("error", mx.error, {"domain": domain}, source)

        errors: dict[str, str] = {}
        data: dict[str, Any] = {
            "domain": domain,
            "mx": _mx(mx),
            "spf": self._spf(resolver, txt, lifetime, budget),
            "dmarc": _tag_record(resolver, f"_dmarc.{domain}", "DMARC1", lifetime, budget),
            "tls_rpt": _tag_record(resolver, f"_smtp._tls.{domain}", "TLSRPTv1", lifetime, budget),
            "bimi": _tag_record(resolver, f"default._bimi.{domain}", "BIMI1", lifetime, budget),
        }
        if isinstance(data["dmarc"].get("record"), str):
            earlier = list(data["dmarc"].get("problems", []))  # e.g. several records
            data["dmarc"].update(parse_dmarc(data["dmarc"]["record"]))
            data["dmarc"]["problems"] = [*earlier, *data["dmarc"]["problems"]]
        if isinstance(data["bimi"].get("record"), str):
            tags = parse_tags(data["bimi"]["record"])
            data["bimi"].update(logo=tags.get("l", "")[:MAX_URI] or None)
        if isinstance(data["tls_rpt"].get("record"), str):
            data["tls_rpt"]["rua"] = _uris(parse_tags(data["tls_rpt"]["record"]).get("rua", ""))
        data["dkim"] = _dkim(resolver, domain, lifetime, budget)
        data["mta_sts"] = self._mta_sts(ctx, resolver, domain, lifetime, budget)
        for name in ("mx", "spf", "dmarc", "dkim", "tls_rpt", "bimi", "mta_sts"):
            if data[name].get("error"):
                errors[name] = str(data[name]["error"])
        data["errors"] = errors
        return CheckOutcome("ok", data=data, source=source)

    # -- SPF

    def _spf(
        self, resolver: ResolverLike, txt: Lookup, lifetime: float, budget: _Budget
    ) -> dict[str, Any]:
        if txt.error:
            return {"found": None, "error": txt.error}
        records = [str(r["value"]) for r in txt.records if is_spf(str(r["value"]))]
        if not records:
            return {"found": False}
        parsed = parse_spf(records[0])
        lookups, complete, senders, verdict = _spf_lookups(resolver, parsed, lifetime, budget)
        # Without an "all" term the record's ``redirect`` decides (RFC 7208 6.1).
        qualifier = parsed["all"] if parsed["all"] is not None else verdict
        problems = list(parsed["problems"])
        if len(records) > 1:
            problems.append("multiple_records")
        if qualifier is None and (parsed["redirect"] is None or complete):
            problems.append("no_all")
        if lookups > 10:
            problems.append("too_many_lookups")
        return {
            "found": True,
            "record": records[0],
            "count": len(records),
            "qualifier": qualifier,
            "qualifier_via": "redirect" if parsed["all"] is None and verdict else None,
            "terms": parsed["terms"],
            "includes": parsed["includes"],
            "redirect": parsed["redirect"],
            "lookups": lookups,
            "lookups_complete": complete,
            "senders": senders,
            "problems": sorted(set(problems)),
        }

    # -- MTA-STS

    def _mta_sts(
        self,
        ctx: CheckContext,
        resolver: ResolverLike,
        domain: str,
        lifetime: float,
        budget: _Budget,
    ) -> dict[str, Any]:
        result = _tag_record(resolver, f"_mta-sts.{domain}", "STSv1", lifetime, budget)
        if not isinstance(result.get("record"), str):
            return result
        result["id"] = parse_tags(result["record"]).get("id", "")[:64] or None
        names = self._names

        def resolve(name: str) -> list[str]:
            return names(ctx.config, name)

        client = self._client_factory(ctx.config, resolve)
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        document = fetch_document(client, url, {"Accept": "text/plain"})
        policy: dict[str, Any] = {"url": url, "fetched": False, "error": document.error}
        response = document.response
        if response is not None:
            policy["status"] = response.status_code
            if response.status_code == 200:
                policy.update(parse_mta_sts_policy(response.text), fetched=True, error=None)
            else:
                policy["error"] = "http_error"
        result["policy"] = policy
        return result


def _mx(lookup: Lookup) -> dict[str, Any]:
    if lookup.error:
        return {"found": None, "error": lookup.error}
    records = [{"preference": r["preference"], "host": r["host"]} for r in lookup.records]
    null_mx = len(records) == 1 and records[0]["host"] in ("", ".")  # RFC 7505: "does not receive"
    hosts = [] if null_mx else records
    providers = sorted(
        {name for record in hosts if (name := _service(str(record["host"]), MAIL_PROVIDERS))}
    )
    return {
        "found": bool(hosts),
        "null_mx": null_mx,
        "records": hosts,
        "providers": providers,
    }


def _tag_record(
    resolver: ResolverLike, name: str, version: str, lifetime: float, budget: _Budget
) -> dict[str, Any]:
    """A ``v=...; k=v`` TXT record at ``name`` (DMARC, TLS-RPT, BIMI, MTA-STS)."""
    if budget.spent:
        return {"found": None, "error": "budget_exceeded"}
    lookup = lookup_records(resolver, name, "TXT", lifetime)
    if lookup.error:
        return {"found": None, "error": lookup.error}
    wanted = f"v={version}".lower()
    records = [
        str(r["value"]).strip()
        for r in lookup.records
        if str(r["value"]).strip().lower().replace(" ", "").startswith(wanted)
    ]
    if not records:
        return {"found": False}
    result: dict[str, Any] = {"found": True, "record": records[0], "count": len(records)}
    if len(records) > 1:
        result["problems"] = ["multiple_records"]
    return result


def _spf_lookups(
    resolver: ResolverLike, parsed: dict[str, Any], lifetime: float, budget: _Budget
) -> tuple[int, bool, list[str], str | None]:
    """The DNS lookups an evaluator spends on this record (RFC 7208 4.6.4), found by following
    ``include`` and ``redirect`` (at most ``MAX_SPF_FETCHES`` fetches), the services named, and
    - when the record has no ``all`` - the ``all`` the redirect chain ends in."""
    total = int(parsed["direct_lookups"])
    complete = True
    queue = [*parsed["includes"], *([parsed["redirect"]] if parsed["redirect"] else [])]
    services = {s for name in queue if (s := _service(str(name), SENDER_SERVICES))}
    deciding = parsed["redirect"] if parsed["all"] is None else None  # whose "all" counts
    verdict: str | None = None
    seen: set[str] = set()
    fetched = 0
    while queue:
        domain = str(queue.pop(0))
        if domain in seen:
            continue
        seen.add(domain)
        if fetched >= MAX_SPF_FETCHES or budget.spent:
            return total, False, sorted(services), verdict
        fetched += 1
        lookup = lookup_records(resolver, domain, "TXT", lifetime)
        if lookup.error:
            complete = False
            continue
        records = [str(r["value"]) for r in lookup.records if is_spf(str(r["value"]))]
        if not records:
            continue
        inner = parse_spf(records[0])
        total += int(inner["direct_lookups"])
        if domain == deciding:
            verdict = inner["all"]
            deciding = inner["redirect"] if inner["all"] is None else None
        for name in [*inner["includes"], *([inner["redirect"]] if inner["redirect"] else [])]:
            queue.append(name)
            service = _service(str(name), SENDER_SERVICES)
            if service:
                services.add(service)
    return total, complete, sorted(services), verdict


def _dkim(resolver: ResolverLike, domain: str, lifetime: float, budget: _Budget) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    revoked: list[str] = []
    checked: list[str] = []
    error: str | None = None
    for selector in DKIM_SELECTORS:
        if budget.spent:
            error = "budget_exceeded"
            break
        lookup = lookup_records(resolver, f"{selector}._domainkey.{domain}", "TXT", lifetime)
        if lookup.error:
            error = lookup.error
            if lookup.error in STOP_AFTER:
                break
            continue
        checked.append(selector)
        for record in lookup.records:
            value = str(record["value"])
            if "p=" in value.lower() and parse_tags(value).get("v", "DKIM1").upper() == "DKIM1":
                key = dkim_key(value)
                if key["revoked"]:  # an empty key withdraws the selector (some zones do it for all)
                    revoked.append(selector)
                else:
                    found.append({"selector": selector, **key})
                break
    return {
        "found": found,
        "revoked": revoked,
        "selectors_checked": checked,
        "error": error if error and not checked else None,
        "incomplete": error is not None,
    }
