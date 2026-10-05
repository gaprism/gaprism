"""What the host views show: a one-line summary per check, and the full detail of one host.

The summaries turn the stored facts into short, translated text with a badge tone. They state
what was *collected* (an expired certificate, a dangling CNAME); judging it (findings and their
severity) is the job of the rules that come later. Every string that comes from the assessed
host is passed through untouched here and escaped by the templates.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks import DISCOVERY_KEY
from app.i18n import gettext as _
from app.i18n import ngettext
from app.models import Assessment, CheckResult, Host, Scan

CHECK_ORDER = ("dns", "ip", "ports", "tls", "http")
# The checks of the domain itself (they run once per scan), in display order.
DOMAIN_CHECK_ORDER = ("email", "registration")
MAX_RAW_JSON_CHARS = 100_000


def N_(message: str) -> str:  # noqa: N802 - the gettext marker: translated when used, not here
    return message


CHECK_TITLES = {
    "dns": N_("DNS"),
    "ip": N_("IP addresses and location"),
    "ports": N_("Open ports and CVEs"),
    "tls": N_("TLS certificate"),
    "http": N_("HTTP"),
    "email": N_("Email security"),
    "registration": N_("Domain registration"),
}

REASONS = {
    "timeout": N_("Timed out"),
    "refused": N_("Connection refused"),
    "servfail": N_("Resolver error"),
    "dns_error": N_("Resolver error"),
    "network_error": N_("Network error"),
    "connection_failed": N_("Connection failed"),
    "handshake_failed": N_("TLS handshake failed"),
    "tls_error": N_("TLS error"),
    "tls_verification_failed": N_("Certificate not trusted"),
    "blocked_destination": N_("Blocked destination"),
    "dns_failed": N_("DNS lookup failed"),
    "protocol_error": N_("Protocol error"),
    "http_error": N_("HTTP error"),
    "nxdomain": N_("Name does not exist"),
    "no_records": N_("No records"),
    "no_web_server": N_("No web server"),
    "no_public_address": N_("No public address to connect to"),
    "no_hostname": N_("No hostname"),
    "no_certificate": N_("No certificate"),
    "internal_error": N_("Internal error"),
    "max_attempts_exceeded": N_("Gave up after repeated failures"),
    "scan_cancelled": N_("Scan cancelled"),
    "unknown_check": N_("Unknown check"),
    "scan_missing": N_("Scan no longer exists"),
    "too_many_redirects": N_("Too many redirects"),
    "cname_loop": N_("CNAME loop"),
    "cname_chain_too_long": N_("CNAME chain too long"),
    "datasets_missing": N_("Location data not installed"),
    "datasets_unreadable": N_("Location data unreadable"),
    "not_in_database": N_("Not in the location database"),
    "no_information": N_("The provider knows nothing about this address"),
    "rate_limited": N_("Rate limited"),
    "invalid_key": N_("API key rejected"),
    "membership_required": N_("Needs a paid Shodan plan"),
    "missing_api_key": N_("No API key configured"),
    "disabled": N_("Switched off"),
    "not_asked": N_("Not asked after an earlier failure"),
    "invalid_response": N_("Unexpected response"),
    "budget_exceeded": N_("Took too long"),
    "no_rdap_service": N_("The registry offers no RDAP service"),
    "not_found": N_("The registry has no such domain"),
    "bootstrap_failed": N_("IANA's list of RDAP servers could not be read"),
    "not_registrable": N_("Not a registrable domain"),
    "not_allowed": N_("The registry refused the request"),
}

# Longer advice for the reasons a person can act on; shown on the host page.
HELP = {
    "datasets_missing": N_(
        "The IP location databases are not installed. Run `flask datasets update` once "
        "(about 65 MB from DB-IP.com) and scan again."
    ),
    "datasets_unreadable": N_(
        "The IP location databases could not be read. Run `flask datasets update --force` "
        "to download them again."
    ),
    "missing_api_key": N_(
        "PORTS_PROVIDER is set to shodan but SHODAN_API_KEY is empty. Add the key to `.env`, "
        "or set PORTS_PROVIDER=auto to use the keyless InternetDB, and scan again."
    ),
    "invalid_key": N_("Shodan rejected the API key. Check SHODAN_API_KEY in `.env`."),
    "membership_required": N_(
        "Shodan says this lookup needs a paid membership. Check the plan of your key, or set "
        "PORTS_PROVIDER=internetdb."
    ),
    "disabled": N_(
        "This lookup is switched off: ports and CVEs by PORTS_PROVIDER=off, lookups of the "
        "domain at a third party by EXTERNAL_DOMAIN_LOOKUPS."
    ),
    "no_rdap_service": N_(
        "IANA's list has no RDAP server for this top-level domain (many country registries only "
        "run WHOIS). The registration details have to be looked up by hand."
    ),
    "rate_limited": N_(
        "The provider's rate limit was reached. Lower SHODAN_RATE_PER_SECOND or "
        "INTERNETDB_RATE_PER_SECOND, or scan again later."
    ),
}

# What is wrong with a mail record, for the problem codes the email check reports.
PROBLEMS = {
    "multiple_records": N_("More than one record: receivers treat this as an error"),
    "no_all": N_("Neither an 'all' term nor a redirect: the default result is neutral"),
    "too_many_lookups": N_("More than 10 DNS lookups: receivers may reject the record"),
    "ptr_used": N_("Uses 'ptr', which is deprecated"),
    "unknown_term": N_("Contains a term that is not valid SPF"),
    "unknown_modifier": N_("Contains a modifier that is not defined in SPF"),
    "invalid_policy": N_("The policy (p=) is missing or not valid"),
    "invalid_subdomain_policy": N_("The subdomain policy (sp=) is not valid"),
    "invalid_pct": N_("The percentage (pct=) is not a number from 0 to 100"),
}

TLS_FAILURES = {
    "expired": N_("Expired"),
    "not_yet_valid": N_("Not yet valid"),
    "hostname_mismatch": N_("Name mismatch"),
    "untrusted": N_("Not trusted"),
    "verify_failed": N_("Verification failed"),
    "handshake_failed": N_("TLS handshake failed"),
}


def reason_label(code: str | None) -> str | None:
    """Translated text for a reason code (``None`` for no reason, the code itself if unknown)."""
    if not code:
        return None
    if code.startswith("needs:"):
        return _("Skipped: %(checks)s did not succeed", checks=code[len("needs:") :])
    if code in REASONS:
        return _(REASONS[code])
    if code.startswith("http_") and code[5:].isdigit():
        return _("HTTP error %(code)s", code=code[5:])
    # A TLS check that read no certificate reports why verification failed as its reason.
    return _(TLS_FAILURES[code]) if code in TLS_FAILURES else code


def problem_label(code: str) -> str:
    return _(PROBLEMS[code]) if code in PROBLEMS else code


def tls_failure_label(code: str) -> str:
    return _(TLS_FAILURES[code]) if code in TLS_FAILURES else code


def reason_help(code: str | None) -> str | None:
    """Advice for a reason code, if there is any."""
    return _(HELP[code]) if code in HELP else None


@dataclass(frozen=True)
class CheckCell:
    """A check's outcome in one line: its status, the badge tone and the text."""

    status: str
    tone: str
    text: str


def _dns_cell(data: Mapping[str, Any]) -> CheckCell:
    addresses = list(data.get("addresses", []))
    blocked = list(data.get("blocked", []))
    if data.get("dangling_cname"):
        return CheckCell("ok", "high", _("Dangling CNAME"))
    if blocked and not addresses:
        return CheckCell("ok", "medium", _("Only private addresses"))
    if blocked:
        text = ngettext(
            "%(num)s address, %(blocked)s private",
            "%(num)s addresses, %(blocked)s private",
            len(addresses),
            blocked=len(blocked),
        )
        return CheckCell("ok", "medium", text)
    if not addresses:
        return CheckCell("ok", "muted", _("No address records"))
    return CheckCell("ok", "ok", ngettext("%(num)s address", "%(num)s addresses", len(addresses)))


def _ip_cell(data: Mapping[str, Any]) -> CheckCell:
    entries = list(data.get("addresses", []))
    located = [entry for entry in entries if entry.get("country")]
    if not located:
        return CheckCell("ok", "muted", _("Network known, location not"))
    if data.get("all_edge"):
        network = next((e["network"]["name"] for e in entries if e.get("network")), "CDN")
        return CheckCell("ok", "muted", _("%(network)s edge", network=network))
    countries = list(data.get("countries", []))
    if len(countries) == 1:
        cities = {entry["city"] for entry in located if entry.get("city")}
        text = f"{countries[0]} · {next(iter(cities))}" if len(cities) == 1 else countries[0]
    else:
        text = ", ".join(countries[:4]) + ("…" if len(countries) > 4 else "")
    if data.get("edge"):
        text += " · " + _("incl. CDN edge")
    return CheckCell("ok", "ok", text)


def _ports_cell(data: Mapping[str, Any]) -> CheckCell:
    """Ports and CVE counts of the addresses that speak for the host (not a CDN's shared edge)."""
    entries = [entry for entry in data.get("addresses", []) if entry.get("facts")]
    own = [entry for entry in entries if entry.get("attribution") != "shared_infrastructure"]
    if not own:
        text, tone = (_("Shared infrastructure"), "muted") if entries else (_("No data"), "muted")
    else:
        ports = {port for entry in own for port in entry["facts"].get("ports", [])}
        cves = {vuln["id"] for entry in own for vuln in entry["facts"].get("vulnerabilities", [])}
        parts = [ngettext("%(num)s port", "%(num)s ports", len(ports))] if ports else []
        if cves:
            parts.append(ngettext("%(num)s CVE", "%(num)s CVEs", len(cves)))
        text, tone = " · ".join(parts) or _("No open ports seen"), "info"
        if len(own) < len(entries):
            text += " · " + _("plus shared")
    if data.get("complete") is False:
        text, tone = text + " · " + _("incomplete"), "medium"
    return CheckCell("ok", tone, text)


_SPF_ALL = {"fail": "-all", "softfail": "~all", "neutral": "?all", "pass": "+all"}


def _email_cell(data: Mapping[str, Any]) -> CheckCell:
    """SPF and DMARC in a few words; the tone says whether the domain can be spoofed."""
    mx = data.get("mx", {})
    spf = data.get("spf", {})
    dmarc = data.get("dmarc", {})
    mail = bool(mx.get("found"))
    parts: list[str] = []
    weak = False
    if spf.get("found"):
        qualifier = spf.get("qualifier")
        without = _("redirect") if spf.get("redirect") else _("without all")
        parts.append("SPF " + _SPF_ALL.get(qualifier, without))
        weak = weak or qualifier not in ("fail", "softfail") or bool(spf.get("problems"))
    elif spf.get("found") is False:
        parts.append(_("No SPF"))
        weak = True
    else:
        parts.append(_("SPF unknown"))
    if dmarc.get("found"):
        policy = dmarc.get("policy")
        parts.append("DMARC " + (policy or _("invalid")))
        weak = weak or policy not in ("quarantine", "reject")
    elif dmarc.get("found") is False:
        parts.append(_("No DMARC"))
        weak = True
    else:
        parts.append(_("DMARC unknown"))
    if spf.get("qualifier") == "pass":
        tone = "high"  # "+all": anyone may send in this domain's name
    elif data.get("errors"):
        tone = "medium"
        parts.append(_("incomplete"))
    elif weak:
        tone = "medium" if mail else "muted"  # a domain that receives no mail matters less
    else:
        tone = "ok"
    return CheckCell("ok", tone, " · ".join(parts))


def _registration_cell(data: Mapping[str, Any]) -> CheckCell:
    """When the domain expires and who registered it, in a few words."""
    days = data.get("days_to_expiry")
    registrar = (data.get("registrar") or {}).get("name")
    if isinstance(days, int):
        if days < 0:
            text = ngettext("Expired %(num)s day ago", "Expired %(num)s days ago", -days)
            tone = "high"
        else:
            text = ngettext("Expires in %(num)s day", "Expires in %(num)s days", days)
            tone = "medium" if days <= 30 else "ok"
    else:
        text, tone = _("No dates published"), "muted"
    return CheckCell("ok", tone, f"{text} · {registrar}" if registrar else text)


def _tls_cell(data: Mapping[str, Any]) -> CheckCell:
    if not data.get("verified"):
        failures = list(data.get("failures", []))
        return CheckCell(
            "ok", "high", tls_failure_label(failures[0] if failures else "verify_failed")
        )
    days = (data.get("certificate") or {}).get("days_remaining")
    if not isinstance(days, int):
        return CheckCell("ok", "ok", _("Valid"))
    if days <= 30:
        return CheckCell(
            "ok", "medium", ngettext("Expires in %(num)s day", "Expires in %(num)s days", days)
        )
    return CheckCell(
        "ok", "ok", ngettext("Valid · %(num)s day left", "Valid · %(num)s days left", days)
    )


def _http_cell(data: Mapping[str, Any]) -> CheckCell:
    status = data.get("status")
    if not isinstance(status, int):
        return CheckCell("ok", "muted", _("Answered"))
    tone = "high" if status >= 500 else "medium" if status >= 400 else "ok"
    if data.get("scheme") == "http":
        return CheckCell("ok", "medium", _("%(status)s · HTTP only", status=status))
    if data.get("redirect_incomplete"):
        return CheckCell("ok", "medium", _("%(status)s · redirect not followed", status=status))
    return CheckCell("ok", tone, str(status))


_SUMMARIES: dict[str, Callable[[Mapping[str, Any]], CheckCell]] = {
    "dns": _dns_cell,
    "ip": _ip_cell,
    "ports": _ports_cell,
    "tls": _tls_cell,
    "http": _http_cell,
    "email": _email_cell,
    "registration": _registration_cell,
}


def summarize(
    check_key: str, status: str, reason_code: str | None, data: Mapping[str, Any]
) -> CheckCell:
    """One line about a check result, for the hosts table and the section headers."""
    if status == "queued":
        return CheckCell(status, "info", _("Queued"))
    if status == "running":
        return CheckCell(status, "info", _("Running"))
    if status == "ok":
        summary = _SUMMARIES.get(check_key)
        return summary(data) if summary else CheckCell(status, "ok", _("Done"))
    reason = reason_label(reason_code)
    if status == "no_data":
        return CheckCell(status, "muted", reason or _("No data"))
    if status == "skipped":
        return CheckCell(status, "muted", reason or _("Skipped"))
    if status == "unavailable":
        return CheckCell(status, "medium", reason or _("Unavailable"))
    return CheckCell(status, "high", reason or _("Failed"))


def check_title(check_key: str) -> str:
    return _(CHECK_TITLES[check_key]) if check_key in CHECK_TITLES else check_key


def _order(check_key: str) -> tuple[int, str]:
    return (CHECK_ORDER.index(check_key), "") if check_key in CHECK_ORDER else (99, check_key)


def _domain_order(check_key: str) -> tuple[int, str]:
    if check_key in DOMAIN_CHECK_ORDER:
        return (DOMAIN_CHECK_ORDER.index(check_key), "")
    return (99, check_key)


@dataclass(frozen=True)
class DomainRow:
    """A domain-level check in one line, for the assessment page."""

    key: str
    title: str
    cell: CheckCell


def domain_rows(session: Session, scan_id: uuid.UUID) -> list[DomainRow]:
    """One line per domain-level check of a scan (discovery has its own panel)."""
    rows = session.execute(
        select(
            CheckResult.check_key, CheckResult.status, CheckResult.reason_code, CheckResult.data
        ).where(
            CheckResult.scan_id == scan_id,
            CheckResult.host_id.is_(None),
            CheckResult.check_key != DISCOVERY_KEY,
        )
    ).all()
    found = [
        DomainRow(key, check_title(key), summarize(key, status, reason_code, data))
        for key, status, reason_code, data in rows
    ]
    return sorted(found, key=lambda row: _domain_order(row.key))


def host_cells(session: Session, host_ids: Sequence[uuid.UUID]) -> dict[Any, dict[str, CheckCell]]:
    """For each host, the one-line summary of each of its checks."""
    if not host_ids:
        return {}
    cells: dict[Any, dict[str, CheckCell]] = {}
    rows = session.execute(
        select(
            CheckResult.host_id,
            CheckResult.check_key,
            CheckResult.status,
            CheckResult.reason_code,
            CheckResult.data,
        ).where(CheckResult.host_id.in_(host_ids))
    )
    for host_id, check_key, status, reason_code, data in rows:
        cells.setdefault(host_id, {})[check_key] = summarize(check_key, status, reason_code, data)
    return cells


# --------------------------------------------------------------------------- one host in full


@dataclass(frozen=True)
class CheckSection:
    """One check of a host, with everything a detail page shows about it."""

    key: str
    title: str
    cell: CheckCell
    reason: str | None
    help: str | None
    data: dict[str, Any]
    collected_at: datetime | None
    duration_ms: int | None
    raw_json: str
    raw_truncated: bool


@dataclass(frozen=True)
class HostDetail:
    host: Host
    scan: Scan
    assessment: Assessment
    sections: list[CheckSection]


def raw_json(data: Mapping[str, Any]) -> tuple[str, bool]:
    """The stored data as readable JSON, cut at ``MAX_RAW_JSON_CHARS``."""
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    return text[:MAX_RAW_JSON_CHARS], len(text) > MAX_RAW_JSON_CHARS


def get_host_detail(session: Session, host_id: uuid.UUID) -> HostDetail | None:
    """A host with its scan, assessment and every check result (``None``: no such host)."""
    host = session.get(Host, host_id)
    scan = session.get(Scan, host.scan_id) if host else None
    assessment = session.get(Assessment, scan.assessment_id) if scan else None
    if host is None or scan is None or assessment is None:
        return None
    results = session.scalars(select(CheckResult).where(CheckResult.host_id == host.id)).all()
    sections = [_section(result) for result in sorted(results, key=lambda r: _order(r.check_key))]
    return HostDetail(host=host, scan=scan, assessment=assessment, sections=sections)


def _section(result: CheckResult) -> CheckSection:
    text, truncated = raw_json(result.data)
    return CheckSection(
        key=result.check_key,
        title=check_title(result.check_key),
        cell=summarize(result.check_key, result.status, result.reason_code, result.data),
        reason=reason_label(result.reason_code),
        help=reason_help(result.reason_code),
        data=dict(result.data),
        collected_at=result.collected_at,
        duration_ms=result.duration_ms,
        raw_json=text,
        raw_truncated=truncated,
    )


@dataclass(frozen=True)
class DomainDetail:
    scan: Scan
    assessment: Assessment
    sections: list[CheckSection]


def get_domain_detail(session: Session, scan: Scan) -> DomainDetail | None:
    """The domain-level checks of a scan, check by check (``None``: the assessment is gone)."""
    assessment = session.get(Assessment, scan.assessment_id)
    if assessment is None:
        return None
    results = session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id,
            CheckResult.host_id.is_(None),
            CheckResult.check_key != DISCOVERY_KEY,
        )
    ).all()
    sections = [_section(r) for r in sorted(results, key=lambda r: _domain_order(r.check_key))]
    return DomainDetail(scan=scan, assessment=assessment, sections=sections)
