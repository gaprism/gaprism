"""Who receives what when a scan runs: the answer to "what leaves our network?".

Built from the configuration, so that a page says what *this* installation does and not what the
defaults would. docs/deploy.md has the same list (section "What leaves your network");
tests/test_disclosure.py keeps the two in step. Nothing here reads a secret: a provider key only
decides which provider is named, and its value never appears.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.checks.reputation import SECURITY_RESOLVERS, SecurityResolver
from app.i18n import gettext as _

# What each name in CT_SOURCES is called and where its requests go.
CT_SOURCES = {
    "ctlogs": ("ctlogs.dev", "api.ctlogs.dev"),
    "certspotter": ("CertSpotter", "api.certspotter.com"),
    "crtsh": ("crt.sh", "crt.sh"),
}

# The optional lookups of EXTERNAL_DOMAIN_LOOKUPS that are on by default, in the order they are
# listed, and the ones that are off until somebody adds them to the setting.
OPTIONAL_LOOKUPS = ("rdap", "hsts_preload", "hibp")
OPT_IN_LOOKUPS = ("observatory",)

# Where `flask datasets update` downloads public files from (the IP location databases, with a
# mirror as a fallback, the exploitation data and the blocklists). Nothing about an assessment is
# sent there.
DATASET_DOWNLOADS = (
    "download.db-ip.com",
    "cdn.jsdelivr.net",
    "www.cisa.gov",
    "epss.empiricalsecurity.com",
    "urlhaus.abuse.ch",
    "feodotracker.abuse.ch",
    "raw.githubusercontent.com",
)


@dataclass(frozen=True)
class Recipient:
    """One party that receives something because a scan runs."""

    key: str  # stable name: "ct", "dns", "hosts", "ports", "reputation", "rdap", ...
    who: str  # as shown
    hosts: tuple[str, ...]  # where the requests go (names or addresses); empty if it varies
    receives: str  # what is sent
    why: str  # what for
    setting: str  # the setting that changes it
    third_party: bool  # false for the assessed domain's own servers
    learns_domain: bool  # does it learn the name of the assessed domain?
    optional: bool  # can it be switched off without losing the scan?


@dataclass(frozen=True)
class Disclosure:
    rows: tuple[Recipient, ...]
    domain_to: tuple[str, ...]  # the third parties that learn the domain name
    optional_off: tuple[str, ...]  # the optional lookups that are switched off here


def _optional(key: str) -> Recipient:
    if key == "observatory":
        return Recipient(
            "observatory",
            _("Mozilla's HTTP Observatory"),
            ("observatory-api.mdn.mozilla.net",),
            _(
                "The domain name. Mozilla's scanner then requests the home page and a few "
                "well-known files from the domain's own servers, which see Mozilla; the scan and "
                "its grade are public on MDN and cannot be hidden"
            ),
            _("An independent grade of the security headers"),
            "EXTERNAL_DOMAIN_LOOKUPS",
            third_party=True,
            learns_domain=True,
            optional=True,
        )
    if key == "rdap":
        return Recipient(
            "rdap",
            _("The registry's RDAP service"),
            ("data.iana.org",),
            _("The domain name (the registry is found through IANA's bootstrap file)"),
            _("Registrar, expiry, locks and DNSSEC"),
            "EXTERNAL_DOMAIN_LOOKUPS",
            third_party=True,
            learns_domain=True,
            optional=True,
        )
    if key == "hsts_preload":
        return Recipient(
            "hsts_preload",
            "hstspreload.org",
            ("hstspreload.org",),
            _("The domain name"),
            _("Whether the domain is on the HSTS preload list"),
            "EXTERNAL_DOMAIN_LOOKUPS",
            third_party=True,
            learns_domain=True,
            optional=True,
        )
    return Recipient(
        "hibp",
        "Have I Been Pwned",
        ("haveibeenpwned.com",),
        _("The domain name"),
        _("Public breaches of services on the domain"),
        "EXTERNAL_DOMAIN_LOOKUPS",
        third_party=True,
        learns_domain=True,
        optional=True,
    )


def _optional_name(key: str) -> str:
    return {
        "rdap": _("the registry (RDAP)"),
        "hsts_preload": "hstspreload.org",
        "hibp": "Have I Been Pwned",
        "observatory": _("Mozilla's HTTP Observatory"),
    }[key]


def _ports(config: Mapping[str, Any]) -> Recipient | None:
    provider = str(config.get("PORTS_PROVIDER", "auto"))
    has_key = bool(config.get("SHODAN_API_KEY"))
    if provider == "off" or (provider == "shodan" and not has_key):
        return None  # nothing is sent (the check says why it has no answer)
    if provider == "shodan" or (provider == "auto" and has_key):
        who, host = _("Shodan (host API)"), "api.shodan.io"
    else:
        who, host = _("Shodan InternetDB"), "internetdb.shodan.io"
    return Recipient(
        "ports",
        who,
        (host,),
        _("The public IP addresses of the hosts, not their names"),
        _("Open ports and known vulnerabilities"),
        "PORTS_PROVIDER",
        third_party=True,
        learns_domain=False,
        optional=True,
    )


def _security_resolvers(config: Mapping[str, Any]) -> list[SecurityResolver]:
    chosen = config.get("REPUTATION_RESOLVERS", [])
    return [SECURITY_RESOLVERS[key] for key in chosen if key in SECURITY_RESOLVERS]


def _reputation(resolvers: list[SecurityResolver]) -> Recipient | None:
    if not resolvers:
        return None  # switched off: nothing is sent
    return Recipient(
        "reputation",
        _("Security DNS resolvers: %(names)s", names=", ".join(r.name for r in resolvers)),
        tuple(r.address for r in resolvers),
        _("Every host name of the assessment, as a plain DNS question like the DNS check's"),
        _("Whether they block a host as malicious (malware, phishing, botnet control)"),
        "REPUTATION_RESOLVERS",
        third_party=True,
        learns_domain=True,
        optional=True,
    )


def describe(config: Mapping[str, Any]) -> Disclosure:
    """The recipients for this configuration. Call it in a request: the texts are translated."""
    ct = [CT_SOURCES[key] for key in config.get("CT_SOURCES", []) if key in CT_SOURCES]
    resolvers = tuple(str(address) for address in config.get("EGRESS_DNS_RESOLVERS", []))
    rows = [
        Recipient(
            "ct",
            _("Certificate Transparency sources: %(names)s", names=", ".join(n for n, _h in ct)),
            tuple(host for _n, host in ct),
            _("The domain name"),
            _("Finding the host names that certificates were issued for"),
            "CT_SOURCES",
            third_party=True,
            learns_domain=True,
            optional=False,
        ),
        Recipient(
            "dns",
            _("DNS resolvers: %(names)s", names=", ".join(resolvers))
            if resolvers
            else _("The system's DNS resolver"),
            resolvers,
            _(
                "Every host name that is looked up: the domain, its hosts "
                "and the mail and policy names"
            ),
            _("The DNS, e-mail and domain checks"),
            "EGRESS_DNS_RESOLVERS",
            third_party=True,
            learns_domain=True,
            optional=False,
        ),
        Recipient(
            "hosts",
            _("The assessed domain's own servers"),
            (),
            _(
                "TLS handshakes and HTTP requests (the home page, security.txt, "
                "the MTA-STS policy), with the User-Agent %(agent)s: "
                "the owner can see the scan in their logs",
                agent=str(config.get("USER_AGENT", "")),
            ),
            _("The TLS, TLS versions, HTTP, subdomain takeover and e-mail checks"),
            "USER_AGENT",
            third_party=False,
            learns_domain=True,
            optional=False,
        ),
    ]
    ports = _ports(config)
    if ports is not None:
        rows.append(ports)
    security = _security_resolvers(config)
    reputation = _reputation(security)
    if reputation is not None:
        rows.append(reputation)
    chosen = config.get("EXTERNAL_DOMAIN_LOOKUPS", [])
    enabled = [key for key in (*OPTIONAL_LOOKUPS, *OPT_IN_LOOKUPS) if key in chosen]
    rows.extend(_optional(key) for key in enabled)

    domain_to = [
        _("the Certificate Transparency sources (%(names)s)", names=", ".join(n for n, _h in ct)),
        _("the DNS resolvers") if resolvers else _("the system's DNS resolver"),
        *(
            [_("the security DNS resolvers (%(names)s)", names=", ".join(r.name for r in security))]
            if security
            else []
        ),
        *(_optional_name(key) for key in enabled),
    ]
    off = tuple(
        [
            *(_optional_name(key) for key in OPTIONAL_LOOKUPS if key not in enabled),
            *([] if security else [_("the security DNS resolvers")]),
        ]
    )
    return Disclosure(tuple(rows), tuple(domain_to), off)
