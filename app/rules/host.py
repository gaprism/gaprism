"""Rules that judge one host: its certificate, its web responses, its DNS and where it is located.

Every rule reads the stored results of the host's checks (``HostFacts``). A check that did not
succeed gives a rule nothing to read, so a host whose TLS check failed has no TLS findings: the
failed check itself is what the coverage report shows, never "all clear".
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from app.rules.base import (
    N_,
    Attribution,
    Confidence,
    Draft,
    HostFacts,
    RuleSettings,
    Severity,
    host_rule,
)

HSTS_MIN_SECONDS = 15_552_000  # six months
SERIOUS_TLS_FAILURES = ("expired", "not_yet_valid", "untrusted", "verify_failed", "other")
WEAK_SIGNATURE_HASHES = ("md2", "md4", "md5", "sha1")
_SESSION_COOKIE = re.compile(r"(sess|sid\b|auth|token|jwt|login|remember|identity)", re.IGNORECASE)
_CSRF_COOKIE = re.compile(r"(csrf|xsrf)", re.IGNORECASE)
_VERSIONED = re.compile(r"\d+\.\d+|/\d")
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def _subject(host: HostFacts) -> str:
    return f"host:{host.hostname}"


def _own_response(http: Any) -> bool:
    """Is the final response the host's own (not a page of another host it redirects to)?"""
    return not http.data.get("cross_host_final")


def _is_html(data: Any) -> bool:
    return "html" in str(data.get("content_type") or "").lower()


# ------------------------------------------------------------------------------ TLS


@host_rule(
    "TLS_INVALID",
    title=N_("Certificate not valid"),
    summary=N_("The TLS certificate of %(host)s is not valid for clients: %(failures)s."),
    advice=N_("Ask the vendor to replace the certificate and to monitor expiry and names."),
    trigger="The certificate was read but fails validation: expired, not yet valid, not trusted "
    "or issued for another name.",
    severities=("medium", "high"),
    checks=("tls",),
    labels={"failures": N_("Problems"), "days_remaining": N_("Days remaining")},
)
def tls_invalid(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    tls = host.ok("tls")
    if tls is None or tls.data.get("verified") is not False:
        return
    failures = [str(code) for code in tls.data.get("failures", [])] or ["verify_failed"]
    severity: Severity = "medium" if set(failures) == {"hostname_mismatch"} else "high"
    yield Draft(
        _subject(host),
        severity,
        "high",
        "hostname_supported",
        {
            "host": host.hostname,
            "failures": failures,
            "days_remaining": (tls.data.get("certificate") or {}).get("days_remaining"),
        },
        (tls.id,),
        host.id,
    )


@host_rule(
    "TLS_EXPIRES_SOON",
    title=N_("Certificate expires soon"),
    summary=N_("The TLS certificate of %(host)s expires in %(days)s days."),
    advice=N_("Renewal should be automated; ask how certificate expiry is monitored."),
    trigger="A valid certificate expires within 30 days (Medium within 7 days).",
    severities=("low", "medium"),
    checks=("tls",),
    labels={"days": N_("Days remaining"), "expires": N_("Expires")},
)
def tls_expires_soon(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    tls = host.ok("tls")
    if tls is None or tls.data.get("verified") is not True:
        return
    certificate = tls.data.get("certificate") or {}
    days = certificate.get("days_remaining")
    if not isinstance(days, int) or days < 0 or days >= 30:
        return
    yield Draft(
        _subject(host),
        "medium" if days < 7 else "low",
        "high",
        "hostname_supported",
        {
            "host": host.hostname,
            "days": days,
            "expires": str(certificate.get("not_after") or "")[:10],
        },
        (tls.id,),
        host.id,
    )


@host_rule(
    "TLS_WEAK_KEY",
    title=N_("Weak certificate key"),
    summary=N_("The certificate of %(host)s uses a weak %(key_type)s key (%(key_bits)s bits)."),
    advice=N_("Keys should be RSA with 2048 bits or more, or elliptic-curve (P-256 or better)."),
    trigger="The certificate's key is RSA below 2048 bits, elliptic-curve below 224 bits, or DSA.",
    severities=("high",),
    checks=("tls",),
    labels={"key_type": N_("Key type"), "key_bits": N_("Key size (bits)")},
)
def tls_weak_key(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    tls = host.ok("tls")
    certificate = (tls.data.get("certificate") if tls else None) or {}
    key_type = str(certificate.get("key_type") or "")
    bits = certificate.get("key_bits")
    weak = (
        key_type == "DSA"
        or (key_type == "RSA" and isinstance(bits, int) and bits < 2048)
        or (key_type == "EC" and isinstance(bits, int) and bits < 224)
    )
    if tls is not None and weak:
        yield Draft(
            _subject(host),
            "high",
            "high",
            "hostname_supported",
            {"host": host.hostname, "key_type": key_type, "key_bits": bits},
            (tls.id,),
            host.id,
        )


@host_rule(
    "TLS_WEAK_SIGNATURE",
    title=N_("Weak certificate signature"),
    summary=N_("The certificate of %(host)s is signed with the weak algorithm %(algorithm)s."),
    advice=N_("Certificates must be signed with SHA-256 or stronger."),
    trigger="The certificate is signed with SHA-1 or MD5 (or older).",
    severities=("high",),
    checks=("tls",),
    labels={"algorithm": N_("Signature algorithm")},
)
def tls_weak_signature(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    tls = host.ok("tls")
    certificate = (tls.data.get("certificate") if tls else None) or {}
    digest = str(certificate.get("signature_hash") or "").lower()
    if tls is not None and digest in WEAK_SIGNATURE_HASHES:
        yield Draft(
            _subject(host),
            "high",
            "high",
            "hostname_supported",
            {"host": host.hostname, "algorithm": certificate.get("signature_algorithm") or digest},
            (tls.id,),
            host.id,
        )


# ------------------------------------------------------------------------------ HTTP


@host_rule(
    "NO_HTTPS",
    title=N_("No HTTPS"),
    summary=N_("%(host)s answers on plain HTTP but offers no HTTPS."),
    advice=N_("Ask the vendor to serve the site over HTTPS only."),
    trigger="HTTPS could not be reached (nothing listening, no answer) while plain HTTP answered.",
    severities=("high",),
    checks=("http",),
    labels={"https_error": N_("Why HTTPS failed")},
)
def no_https(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or http.data.get("scheme") != "http":
        return
    error = http.data.get("https_error")
    if error in ("tls_verification_failed", "tls_error"):
        return  # HTTPS is offered, with a bad certificate: TLS_INVALID covers that
    yield Draft(
        _subject(host),
        "high",
        "high" if error == "refused" else "medium",
        "hostname_supported",
        {"host": host.hostname, "https_error": error},
        (http.id,),
        host.id,
    )


@host_rule(
    "HTTP_NO_HTTPS_REDIRECT",
    title=N_("HTTP is not redirected to HTTPS"),
    summary=N_("%(host)s serves content over plain HTTP instead of redirecting to HTTPS."),
    advice=N_("Port 80 should redirect to HTTPS (or be closed)."),
    trigger="HTTPS works and plain HTTP (port 80) answers without redirecting to HTTPS.",
    severities=("medium",),
    checks=("http",),
    labels={"status": N_("Status on port 80")},
)
def http_no_https_redirect(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or http.data.get("scheme") != "https":
        return
    port80 = http.data.get("http_port80") or {}
    if port80.get("status") is None or port80.get("redirects_to_https") is not False:
        return
    yield Draft(
        _subject(host),
        "medium",
        "high",
        "hostname_supported",
        {"host": host.hostname, "status": port80.get("status")},
        (http.id,),
        host.id,
    )


@host_rule(
    "HSTS_MISSING",
    title=N_("HSTS not set"),
    summary=N_("%(host)s does not send a Strict-Transport-Security header."),
    advice=N_("Send Strict-Transport-Security so browsers stay on HTTPS."),
    trigger="An HTTPS response of the host itself has no Strict-Transport-Security header.",
    severities=("low",),
    checks=("http",),
)
def hsts_missing(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or http.data.get("scheme") != "https" or not _own_response(http):
        return
    if int(http.data.get("status") or 0) >= 400:
        return
    if (http.data.get("security_headers") or {}).get("strict-transport-security") is None:
        yield Draft(
            _subject(host),
            "low",
            "high",
            "hostname_supported",
            {"host": host.hostname},
            (http.id,),
            host.id,
        )


@host_rule(
    "HSTS_WEAK",
    title=N_("HSTS lifetime is short"),
    summary=N_("The Strict-Transport-Security lifetime of %(host)s is %(max_age)s seconds."),
    advice=N_("Use a max-age of at least six months (15552000 seconds)."),
    trigger="Strict-Transport-Security is set but its max-age is under six months.",
    severities=("informational",),
    checks=("http",),
    labels={"max_age": N_("max-age (seconds)")},
)
def hsts_weak(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or http.data.get("scheme") != "https" or not _own_response(http):
        return
    value = (http.data.get("security_headers") or {}).get("strict-transport-security")
    if value is None:
        return
    match = _MAX_AGE.search(str(value))
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MIN_SECONDS:
        yield Draft(
            _subject(host),
            "informational",
            "high",
            "hostname_supported",
            {"host": host.hostname, "max_age": max_age},
            (http.id,),
            host.id,
        )


def _missing_header(host: HostFacts, header: str) -> Iterator[Draft]:
    """A draft when an HTML response of the host's own lacks ``header``."""
    http = host.ok("http")
    if http is None or not _own_response(http) or not _is_html(http.data):
        return
    if int(http.data.get("status") or 0) >= 400:
        return
    if (http.data.get("security_headers") or {}).get(header) is None:
        yield Draft(
            _subject(host),
            "low",
            "high",
            "hostname_supported",
            {"host": host.hostname},
            (http.id,),
            host.id,
        )


@host_rule(
    "CSP_MISSING",
    title=N_("No Content-Security-Policy"),
    summary=N_("%(host)s does not send a Content-Security-Policy header."),
    advice=N_("A Content-Security-Policy limits the damage of injected scripts."),
    trigger="An HTML response of the host itself has no Content-Security-Policy header.",
    severities=("low",),
    checks=("http",),
)
def csp_missing(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    yield from _missing_header(host, "content-security-policy")


@host_rule(
    "XCTO_MISSING",
    title=N_("No X-Content-Type-Options"),
    summary=N_("%(host)s does not send X-Content-Type-Options: nosniff."),
    advice=N_("Send X-Content-Type-Options: nosniff so browsers do not guess content types."),
    trigger="An HTML response of the host itself has no X-Content-Type-Options header.",
    severities=("low",),
    checks=("http",),
)
def xcto_missing(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    yield from _missing_header(host, "x-content-type-options")


@host_rule(
    "FRAME_PROTECTION_MISSING",
    title=N_("No clickjacking protection"),
    summary=N_("%(host)s sets neither X-Frame-Options nor a CSP frame-ancestors directive."),
    advice=N_("Forbid framing with X-Frame-Options or Content-Security-Policy: frame-ancestors."),
    trigger="An HTML response has no X-Frame-Options header and no frame-ancestors in its CSP.",
    severities=("low",),
    checks=("http",),
)
def frame_protection_missing(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None:
        return
    headers = http.data.get("security_headers") or {}
    if "frame-ancestors" in str(headers.get("content-security-policy") or "").lower():
        return
    yield from _missing_header(host, "x-frame-options")


@host_rule(
    "COOKIE_INSECURE",
    title=N_("Session cookie without protection flags"),
    summary=N_(
        "%(host)s sets session-like cookies without the Secure or HttpOnly flag: %(cookies)s."
    ),
    advice=N_("Session cookies should be Secure and HttpOnly (and carry a SameSite attribute)."),
    trigger="A cookie whose name looks like a session or token lacks Secure (on HTTPS) or "
    "HttpOnly (CSRF tokens are exempt from HttpOnly). Cookie values are never stored.",
    severities=("medium",),
    checks=("http",),
    labels={"missing_secure": N_("Without Secure"), "missing_httponly": N_("Without HttpOnly")},
)
def cookie_insecure(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or not _own_response(http):
        return
    https = http.data.get("scheme") == "https"
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    for cookie in http.data.get("cookies") or []:
        name = str(cookie.get("name") or "")
        if not _SESSION_COOKIE.search(name):
            continue
        if https and not cookie.get("secure") and cookie.get("prefix") not in ("host", "secure"):
            missing_secure.append(name)
        if not cookie.get("httponly") and not _CSRF_COOKIE.search(name):
            missing_httponly.append(name)
    names = sorted({*missing_secure, *missing_httponly})
    if names:
        yield Draft(
            _subject(host),
            "medium",
            "high",
            "hostname_supported",
            {
                "host": host.hostname,
                "cookies": names[:10],
                "missing_secure": sorted(missing_secure)[:10],
                "missing_httponly": sorted(missing_httponly)[:10],
            },
            (http.id,),
            host.id,
        )


@host_rule(
    "SERVER_VERSION_DISCLOSED",
    title=N_("Software version disclosed"),
    summary=N_("%(host)s reveals software versions in its response headers: %(versions)s."),
    advice=N_("Hide version numbers from Server and X-Powered-By; they help attackers."),
    trigger="The Server or X-Powered-By header contains a version number.",
    severities=("informational",),
    checks=("http",),
)
def server_version_disclosed(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    http = host.ok("http")
    if http is None or not _own_response(http):
        return
    shown = [
        str(value)
        for value in (http.data.get("server"), http.data.get("powered_by"))
        if value and _VERSIONED.search(str(value))
    ]
    if shown:
        yield Draft(
            _subject(host),
            "informational",
            "high",
            "hostname_supported",
            {"host": host.hostname, "versions": ", ".join(shown)[:200]},
            (http.id,),
            host.id,
        )


# ------------------------------------------------------------------------------ DNS


@host_rule(
    "DANGLING_CNAME",
    title=N_("Alias points nowhere"),
    summary=N_(
        "%(host)s is an alias for %(target)s, which does not exist; if the target can be "
        "claimed, the name can be taken over."
    ),
    advice=N_("Remove the alias, or check that the target cannot be registered by someone else."),
    trigger="The CNAME chain of the host ends in a name that does not exist. Whether the target "
    "can really be claimed is not checked (a takeover test comes later), so confidence is low.",
    severities=("medium",),
    checks=("dns",),
    labels={"target": N_("Missing target")},
)
def dangling_cname(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    dns = host.ok("dns")
    if dns is None or not dns.data.get("dangling_cname"):
        return
    yield Draft(
        _subject(host),
        "medium",
        "low",
        "hostname_supported",
        {"host": host.hostname, "target": dns.data.get("canonical_name")},
        (dns.id,),
        host.id,
    )


@host_rule(
    "DNS_PRIVATE_ADDRESS",
    title=N_("Public name points to a private address"),
    summary=N_("%(host)s resolves to non-public addresses: %(addresses)s."),
    advice=N_("Public DNS should not publish internal addresses; they reveal the network layout."),
    trigger="The host's A or AAAA records contain private, loopback or link-local addresses.",
    severities=("low",),
    checks=("dns",),
)
def dns_private_address(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    dns = host.ok("dns")
    blocked = [b for b in (dns.data.get("blocked") if dns else None) or [] if b.get("ip")]
    if dns is None or not blocked:
        return
    listed = [f"{b['ip']} ({b.get('reason', '?')})" for b in blocked[:5]]
    yield Draft(
        _subject(host),
        "low",
        "high",
        "hostname_supported",
        {"host": host.hostname, "addresses": ", ".join(listed)},
        (dns.id,),
        host.id,
    )


# ------------------------------------------------------------------------------ location


@host_rule(
    "LOCATION_OUTSIDE_EU_CH",
    title=N_("Host located outside the allowed area"),
    summary=N_(
        "%(host)s resolves to an address located in %(countries)s, outside the allowed area."
    ),
    advice=N_(
        "Ask the vendor where the data is processed and stored; the address location is only a "
        "first indication."
    ),
    trigger="A public address of the host is located (by country) outside the allowed area "
    "(EU-27, EEA and CH by default, `DATA_LOCATION_ALLOWED`). Addresses of CDN or anycast "
    "networks show an edge location, not the data centre: when only those are outside the finding "
    "is Medium with low confidence. Addresses of large cloud providers are often registered in a "
    "country other than the region they run in, so confidence is medium there.",
    severities=("medium", "high"),
    checks=("ip",),
    labels={"countries": N_("Countries"), "addresses": N_("Addresses")},
)
def location_outside_area(host: HostFacts, settings: RuleSettings) -> Iterator[Draft]:
    located = host.ok("ip")
    if located is None:
        return
    outside: list[dict[str, Any]] = []
    for entry in located.data.get("addresses", []):
        country = entry.get("country")
        if country and country not in settings.allowed_countries:
            network = entry.get("network") or {}
            outside.append(
                {
                    "ip": entry.get("ip"),
                    "country": country,
                    "city": entry.get("city"),
                    "network": network.get("name"),
                    "kind": network.get("kind"),
                    "edge": bool(network.get("edge")),
                }
            )
    if not outside:
        return
    own = [o for o in outside if not o["edge"]]
    countries = sorted({str(o["country"]) for o in outside})
    severity: Severity
    confidence: Confidence
    attribution: Attribution
    if own:
        confidence = "medium" if any(o["kind"] == "cloud" for o in own) else "high"
        severity, attribution = "high", "hostname_supported"
    else:  # only CDN / anycast edges: where they are announced is not where data is kept
        severity, confidence, attribution = "medium", "low", "shared_infrastructure"
    yield Draft(
        _subject(host),
        severity,
        confidence,
        attribution,
        {
            "host": host.hostname,
            "countries": ", ".join(countries),
            "addresses": [
                f"{o['ip']} ({o['country']}{', ' + str(o['city']) if o['city'] else ''}"
                f"{', ' + str(o['network']) if o['network'] else ''})"
                for o in outside[:8]
            ],
            "edge_only": not own,
        },
        (located.id,),
        host.id,
    )
