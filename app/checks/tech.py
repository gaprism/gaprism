"""Technologies: what the web server, the page and the network in front of a host say it is built
with, and which other organisations it loads things from.

This check sends nothing. It reads what the DNS, IP and HTTP checks stored (the response headers
and cookies, the generator tag, the hosts and files the page loads from, the network hint of the
addresses, the CNAME chain) and applies the ruleset of ``app/checks/tech_rules.py``. So it is about
what the *first page* names, not about what scripts load later (a browser would see more), and a
technology that is not recognised is not one that is absent. A host whose request ended on another
host's page does not get that page's technologies: only the name of the host it led to is read.

The result lists the technologies with the evidence for each (and a version where the evidence
shows one), the CDN and WAF in front of the host, the third-party hosts the page references, hosts
that are known to have served malicious code, and versions that are past their upstream end of
life or have well-known vulnerabilities. When the page could not be read, only headers, DNS and
network can speak, and the result says so.
"""

from __future__ import annotations

import datetime
import functools
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.checks.tech_rules import (
    BY_KEY,
    CATEGORY_ORDER,
    FLAGGED_HOSTS,
    RULESET_DATE,
    TECHNOLOGIES,
    Evidence,
    Found,
    Tech,
    assess_version,
)
from app.service.discovery.psl import registrable_domain

SOURCE = "tech-fingerprints"
MAX_EVIDENCE = 6  # per technology
MAX_THIRD_PARTIES = 40
MAX_DETAIL = 100  # of the evidence shown
MAX_TEXT = 300  # of the evidence read (a version may sit at the end of a long path)


@functools.cache
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _suffix(name: str, suffix: str) -> bool:
    cleaned = name.strip().lower().rstrip(".")
    return cleaned == suffix or cleaned.endswith("." + suffix)


@dataclass
class Inputs:
    """Everything the ruleset looks at, taken from the results of the other checks."""

    headers: dict[str, list[str]] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    generators: list[str] = field(default_factory=list)
    resources: list[Mapping[str, Any]] = field(default_factory=list)
    inline_hosts: list[str] = field(default_factory=list)
    markers: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)
    cnames: list[str] = field(default_factory=list)
    page_read: bool = False
    page_truncated: bool = False
    redirected_to: str | None = None  # the host that answered instead: its page is not this host's
    sources: list[str] = field(default_factory=list)

    def hosts(self) -> Iterable[tuple[str, str]]:
        """(host, kind) of everything the page loads from another host, inline mentions too."""
        if self.redirected_to:
            yield self.redirected_to, "redirect"
        for resource in self.resources:
            if resource.get("host"):
                yield str(resource["host"]), str(resource.get("kind") or "")
        for host in self.inline_hosts:
            yield host, "inline"


def _resource_text(resource: Mapping[str, Any]) -> str:
    version = resource.get("version")
    return f"{resource.get('host') or ''}{resource.get('path') or ''}" + (
        f"?ver={version}" if version else ""
    )


def read_inputs(previous: Mapping[str, CheckOutcome]) -> Inputs:
    """The facts of the other checks' stored results (a result that did not succeed gives none)."""
    inputs = Inputs()
    dns = previous.get("dns")
    if dns is not None and dns.status == "ok":
        inputs.sources.append("dns")
        names = [str(step.get("target", "")) for step in dns.data.get("cname", []) if step]
        inputs.cnames = [name for name in (*names, str(dns.data.get("canonical_name", ""))) if name]
    ip = previous.get("ip")
    if ip is not None and ip.status == "ok":
        inputs.sources.append("ip")
        for entry in ip.data.get("addresses", []):
            network = entry.get("network") if isinstance(entry, Mapping) else None
            if isinstance(network, Mapping) and network.get("name"):
                inputs.networks.add(str(network["name"]))
    http = previous.get("http")
    if http is not None and http.status == "ok" and http.data.get("cross_host_final"):
        inputs.sources.append("http")  # the response is another host's: only its name is read
        inputs.redirected_to = urlsplit(str(http.data.get("final_url") or "")).hostname
    elif http is not None and http.status == "ok":
        inputs.sources.append("http")
        for header in http.data.get("headers", []):
            if isinstance(header, Mapping) and header.get("name"):
                inputs.headers.setdefault(str(header["name"]).lower(), []).append(
                    str(header.get("value", ""))
                )
        inputs.cookies = [
            str(cookie["name"])
            for cookie in http.data.get("cookies", [])
            if isinstance(cookie, Mapping) and cookie.get("name")
        ]
        page = http.data.get("page")
        if isinstance(page, Mapping):
            inputs.page_read = True
            inputs.page_truncated = bool(page.get("truncated"))
            inputs.generators = [str(text) for text in page.get("generator", [])]
            inputs.resources = [r for r in page.get("resources", []) if isinstance(r, Mapping)]
            inputs.inline_hosts = [str(host) for host in page.get("inline_hosts", [])]
            inputs.markers = {str(marker) for marker in page.get("markers", [])}
    return inputs


def match(tech: Tech, inputs: Inputs) -> list[Evidence]:
    """Every reason the inputs give to think that ``tech`` is there (empty: none)."""
    found: list[Evidence] = []

    def add(kind: str, detail: str) -> None:
        item = Evidence(kind, detail[:MAX_TEXT])
        if item not in found:
            found.append(item)

    for name, pattern in tech.headers:
        for value in inputs.headers.get(name, []):
            if not pattern or _regex(pattern).search(value):
                add("header", f"{name}: {value}" if value else name)
                break
    for pattern in tech.cookies:
        for cookie in inputs.cookies:
            if _regex(pattern).match(cookie):
                add("cookie", cookie)
                break
    for pattern in tech.generator:
        for text in inputs.generators:
            if _regex(pattern).search(text):
                add("generator", text)
                break
    for suffix in tech.hosts:
        for host, kind in inputs.hosts():
            if _suffix(host, suffix):
                add("host", f"{host} ({kind})" if kind else host)
                break
    for pattern in tech.paths:
        for resource in inputs.resources:
            if _regex(pattern).search(str(resource.get("path") or "")):
                add("path", _resource_text(resource))
    for marker in tech.markers:
        if marker in inputs.markers:
            add("marker", marker)
    for network in tech.networks:
        if network in inputs.networks:
            add("network", network)
    for suffix in tech.cnames:
        for name in inputs.cnames:
            if _suffix(name, suffix):
                add("cname", name)
                break
    return found


def _version(tech: Tech, evidence: list[Evidence]) -> tuple[str | None, str | None]:
    """The version the evidence shows and the kind of evidence it was read from."""
    for pattern in tech.version:
        for item in evidence:
            text = item.detail
            found = _regex(pattern).search(text)
            if found:
                return found.group(1).rstrip("."), item.kind
    return None, None


def recognise(inputs: Inputs) -> list[Found]:
    """The technologies the inputs show, with what implies what resolved."""
    result: dict[str, Found] = {}
    for tech in TECHNOLOGIES:
        evidence = match(tech, inputs)
        if evidence:
            version, _source = _version(tech, evidence)
            result[tech.key] = Found(tech, evidence, version)
    changed = True
    while changed:  # WooCommerce implies WordPress implies PHP
        changed = False
        for found in list(result.values()):
            for key in found.tech.implies:
                implied = BY_KEY.get(key)
                if implied is not None and key not in result:
                    result[key] = Found(
                        implied,
                        [Evidence("implied", f"comes with {found.tech.name}")],
                        implied_by=found.tech.name,
                    )
                    changed = True
    return sorted(
        result.values(), key=lambda f: (CATEGORY_ORDER[f.tech.category], f.tech.name.lower())
    )


def _confidence(found: Found) -> str:
    kinds = {item.kind for item in found.evidence}
    if found.implied_by or found.tech.confidence != "high":
        return "medium"
    if kinds <= {"path"} and found.tech.loose_paths:
        return "medium"  # a file called jquery.js is probably jQuery, not certainly
    return "high"


def _is_service(found: Found) -> bool:
    kinds = {item.kind for item in found.evidence}
    if found.implied_by:
        return False
    if found.tech.self_hostable and kinds <= {"path", "marker"}:
        return False  # a script of its own at the site does not show a third party
    return found.tech.is_service


def _entry(found: Found) -> dict[str, Any]:
    _, source = _version(found.tech, found.evidence)
    return {
        "key": found.tech.key,
        "name": found.tech.name,
        "category": found.tech.category,
        "vendor": found.tech.vendor,
        "version": found.version,
        "version_from": source if found.version else None,
        "service": _is_service(found),
        "confidence": _confidence(found),
        "implied_by": found.implied_by,
        "evidence": [
            {"kind": item.kind, "detail": item.detail[:MAX_DETAIL]}
            for item in found.evidence[:MAX_EVIDENCE]
        ],
    }


def _host_owners() -> list[tuple[str, Tech]]:
    """Every host suffix of the ruleset with the entry it belongs to, longest suffix first (so a
    more specific host wins over a general one)."""
    pairs = [(suffix, tech) for tech in TECHNOLOGIES for suffix in (*tech.hosts, *tech.owns)]
    return sorted(pairs, key=lambda pair: -len(pair[0]))


HOST_OWNERS = _host_owners()


def third_parties(inputs: Inputs, hostname: str) -> list[dict[str, Any]]:
    """The other hosts the page loads from, by host; the ones the ruleset knows come first, with
    the vendor (a vendor is named whether or not the page also showed the technology itself)."""
    own = registrable_domain(hostname) or hostname
    seen: dict[str, dict[str, Any]] = {}
    for host, kind in inputs.hosts():
        domain = registrable_domain(host) or host
        if domain == own:
            continue
        row = seen.setdefault(
            host, {"host": host, "domain": domain, "vendor": None, "technology": None, "kinds": []}
        )
        if kind and kind not in row["kinds"]:
            row["kinds"].append(kind)
        for suffix, tech in HOST_OWNERS:
            if _suffix(host, suffix):
                row["technology"] = tech.key
                row["vendor"] = tech.vendor or tech.name
                break
    ordered = sorted(
        seen.values(), key=lambda row: (row["technology"] is None, row["domain"], row["host"])
    )
    return ordered[:MAX_THIRD_PARTIES]


def flagged_hosts(inputs: Inputs) -> list[dict[str, Any]]:
    """Hosts that the page loads from and that are known to have served malicious code, with how
    the page names each (a script is code that runs, an image is not)."""
    flagged: dict[str, dict[str, Any]] = {}
    for host, kind in inputs.hosts():
        for suffix, reason in FLAGGED_HOSTS.items():
            if _suffix(host, suffix):
                row = flagged.setdefault(host, {"host": host, "reason": reason, "kinds": []})
                if kind and kind not in row["kinds"]:
                    row["kinds"].append(kind)
    return list(flagged.values())


class TechCheck:
    """Recognise the technologies behind a host from what the other checks stored."""

    key = "tech"
    scope: CheckScope = "host"
    needs: tuple[str, ...] = ("dns",)
    after: tuple[str, ...] = ("ip", "http")

    def __init__(self, clock: Callable[[], datetime.date] | None = None) -> None:
        self._today = clock or (lambda: datetime.datetime.now(datetime.UTC).date())

    def run(self, ctx: CheckContext) -> CheckOutcome:
        inputs = read_inputs(ctx.previous)
        found = recognise(inputs)
        today = self._today()
        outdated: list[dict[str, Any]] = []
        for item in found:
            verdict = assess_version(item.tech.key, item.version, today)
            if verdict is not None and item.version:
                _, source = _version(item.tech, item.evidence)
                outdated.append(
                    {
                        "key": item.tech.key,
                        "name": item.tech.name,
                        "version": item.version,
                        "reason": verdict["reason"],
                        "detail": verdict["detail"],
                        "since": verdict["since"] or None,
                        "version_from": source,
                    }
                )
        entries = [_entry(item) for item in found]
        data: dict[str, Any] = {
            "technologies": entries,
            "edge": [item.tech.name for item in found if item.tech.category == "edge"],
            # who else operates something the page's visitors reach (the summary reads only this)
            "services": [
                {"name": e["name"], "vendor": e["vendor"], "category": e["category"]}
                for e in entries
                if e["service"] and e["category"] != "edge"
            ],
            "third_parties": third_parties(inputs, ctx.hostname or ""),
            "flagged": flagged_hosts(inputs),
            "outdated": outdated,
            "page": {
                "read": inputs.page_read,
                "truncated": inputs.page_truncated,
                "redirected_to": inputs.redirected_to,
            },
            "sources": inputs.sources,
            "ruleset": RULESET_DATE,
        }
        return CheckOutcome("ok", data=data, source=SOURCE)
