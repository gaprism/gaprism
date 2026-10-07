"""Scans that between them trip every rule, built from the real checks' outputs."""

from __future__ import annotations

import copy
import functools
from collections.abc import Callable
from typing import Any, TypeVar

from app.checks.base import CheckOutcome
from app.rules import ScanFacts
from app.service.geo import IpLocation
from app.service.ports import PortFacts, PortService, PortsLookup, Vulnerability
from tests.checks.test_breaches_check import answering
from tests.checks.test_breaches_check import run as run_breaches
from tests.checks.test_domain_dns_check import addresses as ns_addresses
from tests.checks.test_domain_dns_check import ns_records
from tests.checks.test_domain_dns_check import run as run_domain_dns
from tests.checks.test_email_check import mail_domain, policy_site, txt
from tests.checks.test_email_check import run as run_email
from tests.checks.test_ip_check import FakeProvider, cloudflare, dns_outcome, swiss
from tests.checks.test_ip_check import run as run_ip
from tests.checks.test_ports_check import FakeProvider as PortsProvider
from tests.checks.test_ports_check import dns as ports_dns
from tests.checks.test_ports_check import run as run_ports
from tests.checks.test_registration_check import Registry
from tests.checks.test_registration_check import run as run_registration
from tests.checks.test_securitytxt_check import GITHUB as SECURITY_TXT
from tests.checks.test_securitytxt_check import WELL_KNOWN, Web
from tests.checks.test_securitytxt_check import run as run_security
from tests.checks.test_securitytxt_check import text as security_text
from tests.checks.test_takeover_check import GITHUB_UNCLAIMED
from tests.checks.test_takeover_check import HOST as TAKEOVER_HOST
from tests.checks.test_takeover_check import Web as TakeoverWeb
from tests.checks.test_takeover_check import dns as takeover_dns
from tests.checks.test_takeover_check import html as takeover_html
from tests.checks.test_takeover_check import run as run_takeover
from tests.rules.helpers import DOMAIN, domain_facts, expired, host, http_only, tls, web

T = TypeVar("T")


def cached(build: Callable[[], T]) -> Callable[[], T]:
    """Build once per process and hand out copies: running the real checks over their fixtures
    takes seconds, and many tests want these scenarios. (Also: the breach check's rate limiter is
    process-wide, so it must run only once.)"""
    stored: list[T] = []

    @functools.wraps(build)
    def get() -> T:
        if not stored:
            stored.append(build())
        return copy.deepcopy(stored[0])

    return get


US = IpLocation("198.51.100.7", "US", "United States", "NA", "Virginia", "Ashburn", 39.0, -77.5)
RISKY = (
    PortService(22, "tcp", "OpenSSH", "7.4"),
    PortService(3306, "tcp", "MySQL", "5.7"),
    PortService(443, "tcp", "nginx", "1.24"),
)
CVES = (Vulnerability("CVE-2021-0001", 9.8, None, True), Vulnerability("CVE-2020-0002", 4.0))


def ports(hostname: str, address: str = "93.184.216.34") -> CheckOutcome:
    facts = PortFacts(
        ip=address,
        provider="shodan",
        services=RISKY,
        vulnerabilities=CVES,
        hostnames=(hostname,),
    )
    return run_ports(
        PortsProvider({address: PortsLookup("ok", facts=facts)}),
        {"dns": ports_dns(address)},
        hostname=hostname,
    )


def located(*locations: IpLocation) -> CheckOutcome:
    table = {location.ip: location for location in locations}
    return run_ip(FakeProvider(table), dns_outcome(*table))


@cached
def hosts() -> list[Any]:
    insecure_cookies = [("Set-Cookie", "sid=SECRET; Path=/"), ("Set-Cookie", "PHPSESSID=SECRET")]
    server = [("Server", "nginx/1.10.3")]
    return [
        # a certificate that is expired, weak and badly signed; no security headers; cookies
        host(
            f"bad-tls.{DOMAIN}",
            tls=expired(key_type="RSA", key_bits=1024, signature_hash="sha1"),
            http=web([*server, *insecure_cookies], port80="page"),
            ports=ports(f"bad-tls.{DOMAIN}"),
            dns=CheckOutcome("ok", data={"addresses": ["93.184.216.34"], "blocked": []}),
        ),
        # a valid certificate that runs out in five days and a short HSTS lifetime
        host(
            f"soon.{DOMAIN}",
            tls=tls(days_until_expiration=5),
            http=web([("Strict-Transport-Security", "max-age=300")]),
        ),
        # plain HTTP only, a dangling alias, a private address, located in the US
        host(
            f"plain.{DOMAIN}",
            http=http_only(),
            dns=CheckOutcome(
                "ok",
                data={
                    "dangling_cname": True,
                    "canonical_name": "gone.example.net",
                    "addresses": [],
                    "blocked": [{"ip": "10.0.0.5", "reason": "private"}],
                },
            ),
            ip=located(US, swiss()),
        ),
        # only a CDN edge outside the area
        host(f"cdn.{DOMAIN}", ip=located(cloudflare())),
    ]


@cached
def takeover_hosts() -> list[Any]:
    """Aliases for hosted services: a page that says nobody has claimed the name, and a name that
    does not exist where anyone may register it."""
    unclaimed = takeover_dns("vendor.github.io")
    page = TakeoverWeb({("http", TAKEOVER_HOST): takeover_html(404, GITHUB_UNCLAIMED)})
    missing = takeover_dns("vendor.azurewebsites.net", addresses=(), dangling=True)
    return [
        host(f"shop.{DOMAIN}", dns=unclaimed, takeover=run_takeover(page, unclaimed)),
        host(f"old.{DOMAIN}", dns=missing, takeover=run_takeover(TakeoverWeb(), missing)),
    ]


@cached
def sound_domain() -> dict[str, CheckOutcome]:
    """The checks of a domain with nothing to complain about."""
    return {
        "email": run_email(mail_domain(), policy_site)[0],
        "registration": run_registration("example.com", Registry()),
        "security_txt": run_security(
            Web({("github.com", WELL_KNOWN): security_text(SECURITY_TXT)}), "github.com"
        ),
        "breaches": run_breaches(answering([]), DOMAIN),
    }


@cached
def domain_with_gaps() -> dict[str, CheckOutcome]:
    """No SPF, no DMARC, no MTA-STS; young, unlocked, unsigned; no security.txt; poor DNS."""
    script = mail_domain()
    for key in (
        (DOMAIN, "TXT"),
        (f"_dmarc.{DOMAIN}", "TXT"),
        (f"_mta-sts.{DOMAIN}", "TXT"),
    ):
        script.pop(key, None)
    registration = run_registration("example.com", Registry())
    registration.data.update(
        dnssec=False,
        days_to_expiry=12,
        age_days=30,
        statuses=["client delete prohibited"],
        transfer_locked=False,
    )
    dns_script: dict[tuple[str, str], Any] = {
        (DOMAIN, "NS"): ns_records(DOMAIN, "ns1.a.net", "ns2.b.org"),
        **ns_addresses("ns1.a.net", "198.51.100.1"),  # the second server has no address
    }
    return {
        "email": run_email(script, policy_site)[0],
        "registration": registration,
        "security_txt": run_security(Web()),
        "domain_dns": run_domain_dns(dns_script)[0],
    }


@cached
def domain_with_weak_records() -> dict[str, CheckOutcome]:
    """An SPF that allows everyone, a DMARC that only monitors, a recent breach, a dead file."""
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 +all")
    script[(f"_dmarc.{DOMAIN}", "TXT")] = txt(f"_dmarc.{DOMAIN}", "v=DMARC1; p=none")
    breach = {
        "Name": "Recent",
        "Title": "Recent breach",
        "Domain": DOMAIN,
        "BreachDate": "2026-03-01",
        "PwnCount": 1000,
        "DataClasses": ["Passwords"],
        "IsVerified": True,
    }
    old_file = SECURITY_TXT.replace(
        next(
            line.split(": ", 1)[1]
            for line in SECURITY_TXT.splitlines()
            if line.startswith("Expires:")
        ),
        "2020-01-01T00:00:00Z",
    )
    return {
        "email": run_email(script, policy_site)[0],
        "breaches": run_breaches(answering([breach]), DOMAIN),
        "security_txt": run_security(Web({("example.com", WELL_KNOWN): security_text(old_file)})),
    }


@cached
def domain_with_broken_records() -> dict[str, CheckOutcome]:
    """Two SPF records, an invalid DMARC policy, and a lonely name server without CAA."""
    script = mail_domain()
    script[(DOMAIN, "TXT")] = txt(DOMAIN, "v=spf1 -all", "v=spf1 include:_spf.google.com -all")
    script[(f"_dmarc.{DOMAIN}", "TXT")] = txt(f"_dmarc.{DOMAIN}", "v=DMARC1; p=banana")
    dns_script: dict[tuple[str, str], Any] = {
        (DOMAIN, "NS"): ns_records(DOMAIN, "ns1.a.net"),
        **ns_addresses("ns1.a.net", "198.51.100.1"),
    }
    return {
        "email": run_email(script, policy_site)[0],
        "domain_dns": run_domain_dns(dns_script)[0],
    }


def scans() -> list[ScanFacts]:
    """Together these trip every rule."""
    return [
        ScanFacts(DOMAIN, hosts(), domain_facts(**domain_with_gaps()).results),
        ScanFacts(DOMAIN, [], domain_facts(**domain_with_weak_records()).results),
        ScanFacts(DOMAIN, [], domain_facts(**domain_with_broken_records()).results),
        ScanFacts(DOMAIN, takeover_hosts(), {}),
    ]
