"""Rules that judge the domain itself: email security, registration, security.txt, breaches, DNS.

These read the domain-level check results. A part that could not be asked (``found: null``) is
never judged: not knowing is not a weakness, and the coverage report says what is missing.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import date, datetime
from typing import Any

from app.rules.base import (
    N_,
    Confidence,
    DomainFacts,
    Draft,
    RuleSettings,
    Severity,
    domain_rule,
)

DAYS_PER_MONTH = 30.4375
SECURITY_TXT_BROKEN = (
    "missing_contact",
    "missing_expires",
    "invalid_expires",
    "multiple_expires",
    "expired",
)


def _subject(domain: DomainFacts) -> str:
    return f"domain:{domain.domain}"


def _draft(
    domain: DomainFacts,
    severity: Severity,
    confidence: Confidence,
    params: dict[str, Any],
    result_id: str,
    subject: str | None = None,
) -> Draft:
    return Draft(subject or _subject(domain), severity, confidence, "domain", params, (result_id,))


def _receives_mail(email: Mapping[str, Any]) -> bool:
    return bool((email.get("mx") or {}).get("found"))


# ------------------------------------------------------------------------------ email: SPF


@domain_rule(
    "SPF_MISSING",
    title=N_("No SPF record"),
    summary=N_(
        "%(domain)s publishes no SPF record, so receivers cannot tell forged mail from real."
    ),
    advice=N_(
        "Publish an SPF record; a domain that sends no mail should say so with `v=spf1 -all`."
    ),
    trigger="The domain has no SPF record. Medium if it has mail servers, Low if it does not "
    "(a domain without mail can still be spoofed).",
    severities=("low", "medium"),
    checks=("email",),
)
def spf_missing(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    if email is None or (email.data.get("spf") or {}).get("found") is not False:
        return
    severity: Severity = "medium" if _receives_mail(email.data) else "low"
    yield _draft(domain, severity, "high", {"domain": domain.domain}, email.id)


@domain_rule(
    "SPF_PERMISSIVE",
    title=N_("SPF does not restrict senders"),
    summary=N_(
        "The SPF record of %(domain)s ends in %(ending)s, which does not tell receivers to "
        "reject mail from other senders."
    ),
    advice=N_("End the record with `-all` (or `~all` while rolling it out)."),
    trigger="The SPF record ends in `+all` (High: anyone may send), in `?all` or has no `all` or "
    "redirect at all (Medium: neutral, no protection).",
    severities=("medium", "high"),
    checks=("email",),
    labels={"ending": N_("Record ends in")},
)
def spf_permissive(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    spf = (email.data.get("spf") if email else None) or {}
    if email is None or spf.get("found") is not True:
        return
    qualifier = spf.get("qualifier")
    if qualifier == "pass":
        yield _draft(domain, "high", "high", {"domain": domain.domain, "ending": "+all"}, email.id)
    elif qualifier == "neutral":
        yield _draft(
            domain, "medium", "medium", {"domain": domain.domain, "ending": "?all"}, email.id
        )
    elif qualifier is None and "no_all" in spf.get("problems", []):
        ending = "no all term"
        yield _draft(
            domain, "medium", "medium", {"domain": domain.domain, "ending": ending}, email.id
        )


@domain_rule(
    "SPF_INVALID",
    title=N_("SPF record is broken"),
    summary=N_("The SPF record of %(domain)s is invalid for receivers: %(problems)s."),
    advice=N_("Publish a single SPF record that needs at most 10 DNS lookups."),
    trigger="There is more than one SPF record, or evaluating it needs more than 10 DNS lookups; "
    "receivers treat both as an error, so the record protects nothing.",
    severities=("medium",),
    checks=("email",),
    labels={"problems": N_("Problems"), "lookups": N_("DNS lookups")},
)
def spf_invalid(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    spf = (email.data.get("spf") if email else None) or {}
    problems = [p for p in spf.get("problems", []) if p in ("multiple_records", "too_many_lookups")]
    if email is not None and spf.get("found") is True and problems:
        params = {"domain": domain.domain, "problems": problems, "lookups": spf.get("lookups")}
        yield _draft(domain, "medium", "high", params, email.id)


# ------------------------------------------------------------------------------ email: DMARC etc.


@domain_rule(
    "DMARC_MISSING",
    title=N_("No DMARC record"),
    summary=N_(
        "%(domain)s publishes no DMARC policy, so receivers have no instruction for forged mail."
    ),
    advice=N_(
        "Publish a DMARC record, starting with `p=none` and reporting, then move to `reject`."
    ),
    trigger="The domain has no DMARC record. Medium if it has mail servers, Low if it does not.",
    severities=("low", "medium"),
    checks=("email",),
)
def dmarc_missing(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    if email is None or (email.data.get("dmarc") or {}).get("found") is not False:
        return
    severity: Severity = "medium" if _receives_mail(email.data) else "low"
    yield _draft(domain, severity, "high", {"domain": domain.domain}, email.id)


@domain_rule(
    "DMARC_POLICY_NONE",
    title=N_("DMARC only monitors"),
    summary=N_(
        "The DMARC policy of %(domain)s is `none`: forged mail is reported but still delivered."
    ),
    advice=N_("Once the reports look clean, move the policy to `quarantine` and then `reject`."),
    trigger="A DMARC record exists with `p=none`.",
    severities=("low",),
    checks=("email",),
    labels={"rua": N_("Aggregate reports sent to")},
)
def dmarc_policy_none(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    dmarc = (email.data.get("dmarc") if email else None) or {}
    if email is not None and dmarc.get("found") is True and dmarc.get("policy") == "none":
        params = {"domain": domain.domain, "rua": list(dmarc.get("rua", []))[:3]}
        yield _draft(domain, "low", "high", params, email.id)


@domain_rule(
    "DMARC_INVALID",
    title=N_("DMARC record is broken"),
    summary=N_(
        "The DMARC record of %(domain)s is not valid, so receivers ignore it: %(problems)s."
    ),
    advice=N_("Publish a single DMARC record with a valid `p=` policy."),
    trigger="A DMARC record exists but has no valid policy, or there is more than one record.",
    severities=("medium",),
    checks=("email",),
    labels={"problems": N_("Problems")},
)
def dmarc_invalid(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    dmarc = (email.data.get("dmarc") if email else None) or {}
    if email is None or dmarc.get("found") is not True:
        return
    problems = list(dmarc.get("problems", []))
    if dmarc.get("policy") is None or "multiple_records" in problems:
        yield _draft(
            domain, "medium", "high", {"domain": domain.domain, "problems": problems}, email.id
        )


@domain_rule(
    "MTA_STS_MISSING",
    title=N_("No MTA-STS policy"),
    summary=N_(
        "%(domain)s receives mail but publishes no MTA-STS policy, so mail can be downgraded "
        "in transit."
    ),
    advice=N_("Publish an MTA-STS policy (and TLS-RPT reporting) so senders insist on TLS."),
    trigger="The domain has mail servers and no MTA-STS record.",
    severities=("informational",),
    checks=("email",),
)
def mta_sts_missing(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    email = domain.ok("email")
    if email is None or not _receives_mail(email.data):
        return
    if (email.data.get("mta_sts") or {}).get("found") is False:
        yield _draft(domain, "informational", "high", {"domain": domain.domain}, email.id)


# ------------------------------------------------------------------------------ registration


@domain_rule(
    "DNSSEC_NOT_ENABLED",
    title=N_("DNSSEC is not enabled"),
    summary=N_("The domain %(domain)s is not signed with DNSSEC."),
    advice=N_("DNSSEC protects DNS answers from forgery; ask whether it is planned."),
    trigger="The registry reports that the delegation is not signed.",
    severities=("informational",),
    checks=("registration",),
)
def dnssec_not_enabled(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    registration = domain.ok("registration")
    if registration is not None and registration.data.get("dnssec") is False:
        yield _draft(domain, "informational", "high", {"domain": domain.domain}, registration.id)


@domain_rule(
    "DOMAIN_EXPIRES_SOON",
    title=N_("Domain registration expires soon"),
    summary=N_("The registration of %(domain)s runs out on %(expires)s (days left: %(days)s)."),
    advice=N_("Ask whether auto-renewal is on and who is responsible for the registration."),
    trigger="The registry's expiry date is within 30 days (Medium) or has passed (High). "
    "Registries that publish no dates (such as .ch) cannot be judged.",
    severities=("medium", "high"),
    checks=("registration",),
    labels={"days": N_("Days left"), "expires": N_("Expires")},
)
def domain_expires_soon(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    registration = domain.ok("registration")
    days = registration.data.get("days_to_expiry") if registration else None
    if registration is None or not isinstance(days, int) or days >= 30:
        return
    severity: Severity = "high" if days < 0 else "medium"
    params = {
        "domain": domain.domain,
        "days": days,
        "expires": str(registration.data.get("expires") or "")[:10],
    }
    yield _draft(domain, severity, "high", params, registration.id)


@domain_rule(
    "DOMAIN_RECENTLY_REGISTERED",
    title=N_("Domain registered recently"),
    summary=N_("%(domain)s was registered %(age)s days ago."),
    advice=N_("A young domain has no track record; check who the vendor is before relying on it."),
    trigger="The registration date is less than 90 days ago.",
    severities=("informational",),
    checks=("registration",),
    labels={"created": N_("Registered")},
)
def domain_recently_registered(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    registration = domain.ok("registration")
    age = registration.data.get("age_days") if registration else None
    if registration is not None and isinstance(age, int) and age < 90:
        params = {
            "domain": domain.domain,
            "age": max(age, 0),
            "created": str(registration.data.get("created") or "")[:10],
        }
        yield _draft(domain, "informational", "high", params, registration.id)


@domain_rule(
    "DOMAIN_NOT_LOCKED",
    title=N_("Domain has no transfer lock"),
    summary=N_("%(domain)s can be transferred to another registrar without a lock in the way."),
    advice=N_("Ask the registrar to set the transfer lock (clientTransferProhibited)."),
    trigger="The registry publishes EPP status flags but none of them forbids a transfer. "
    "Registries that publish no lock concept are not judged.",
    severities=("low",),
    checks=("registration",),
    labels={"statuses": N_("Status flags")},
)
def domain_not_locked(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    registration = domain.ok("registration")
    statuses = [str(s) for s in (registration.data.get("statuses") if registration else None) or []]
    epp = any(s.startswith(("client ", "server ")) for s in statuses)
    if registration is not None and epp and not registration.data.get("transfer_locked"):
        params = {"domain": domain.domain, "statuses": statuses[:8]}
        yield _draft(domain, "low", "medium", params, registration.id)


# ------------------------------------------------------------------------------ breaches


def _months_since(day: str | None, now: datetime) -> float | None:
    if not day:
        return None
    try:
        then = date.fromisoformat(day[:10])
    except ValueError:
        return None
    return (now.date() - then).days / DAYS_PER_MONTH


@domain_rule(
    "PUBLIC_BREACH_HISTORY",
    title=N_("Public breach on record"),
    summary=N_("Have I Been Pwned lists a breach of %(domain)s: %(title)s (%(breach_date)s)."),
    advice=N_(
        "Ask what happened, what was done about it and whether the data was protected "
        "(for example hashed passwords)."
    ),
    trigger="Have I Been Pwned documents a breach of a service on the domain. Fabricated entries, "
    "spam lists and retired breaches are ignored. Medium; High if the breach happened within "
    "`BREACH_RECENT_MONTHS` (24 by default). One finding per breach, so each can be accepted on "
    "its own.",
    severities=("medium", "high"),
    checks=("breaches",),
    labels={
        "accounts": N_("Accounts"),
        "data_classes": N_("Data exposed"),
        "verified": N_("Verified by HIBP"),
        "months_ago": N_("Months ago"),
    },
)
def public_breach_history(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    breaches = domain.ok("breaches")
    if breaches is None:
        return
    scope = str(breaches.data.get("queried") or domain.domain)
    for breach in breaches.data.get("breaches", []):
        if breach.get("fabricated") or breach.get("spam_list") or breach.get("retired"):
            continue
        site = str(breach.get("domain") or "")
        if site and site != scope and not site.endswith("." + scope):
            continue  # a breach of someone else's service that merely lists this domain
        months = _months_since(breach.get("breach_date"), settings.now)
        recent = months is not None and months <= settings.breach_recent_months
        severity: Severity = "high" if recent else "medium"
        confidence: Confidence = "high" if breach.get("verified") else "medium"
        if months is None:
            confidence = "low"  # without a date the recency cannot be judged
        name = str(breach.get("name") or "")
        yield Draft(
            f"domain:{domain.domain}:breach:{name}",
            severity,
            confidence,
            "domain",
            {
                "domain": domain.domain,
                "name": name,
                "title": breach.get("title") or name,
                "breach_date": breach.get("breach_date") or "unknown date",
                "months_ago": round(months) if months is not None else None,
                "accounts": breach.get("pwn_count"),
                "data_classes": list(breach.get("data_classes", []))[:8],
                "verified": bool(breach.get("verified")),
            },
            (breaches.id,),
        )


# ------------------------------------------------------------------------------ security.txt


@domain_rule(
    "SECURITY_TXT_MISSING",
    title=N_("No security.txt"),
    summary=N_(
        "%(domain)s publishes no security.txt, so there is no stated way to report a vulnerability."
    ),
    advice=N_("Publish /.well-known/security.txt (RFC 9116) with a contact and an expiry date."),
    trigger="Neither /.well-known/security.txt nor /security.txt was found.",
    severities=("informational",),
    checks=("security_txt",),
)
def security_txt_missing(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    result = domain.result("security_txt")
    if (
        result is not None
        and result.status == "no_data"
        and result.reason_code == "no_security_txt"
    ):
        yield _draft(domain, "informational", "medium", {"domain": domain.domain}, result.id)


@domain_rule(
    "SECURITY_TXT_INVALID",
    title=N_("security.txt is unusable"),
    summary=N_("The security.txt of %(domain)s has problems: %(problems)s."),
    advice=N_("Keep security.txt current: a contact, a future expiry date, one Expires field."),
    trigger="A security.txt was found but has no contact, no valid or a repeated Expires field, "
    "or has expired.",
    severities=("low",),
    checks=("security_txt",),
    labels={"problems": N_("Problems"), "url": N_("Found at")},
)
def security_txt_invalid(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    result = domain.ok("security_txt")
    problems = [
        p
        for p in (result.data.get("problems") if result else None) or []
        if p in SECURITY_TXT_BROKEN
    ]
    if result is not None and problems:
        params = {"domain": domain.domain, "problems": problems, "url": result.data.get("url")}
        yield _draft(domain, "low", "high", params, result.id)


# ------------------------------------------------------------------------------ DNS set-up


@domain_rule(
    "CAA_MISSING",
    title=N_("No CAA records"),
    summary=N_("%(domain)s has no CAA records, so any certificate authority may issue for it."),
    advice=N_("Publish CAA records naming the certificate authorities you use."),
    trigger="No CAA record exists at the domain or any parent name up to its zone.",
    severities=("informational",),
    checks=("domain_dns",),
)
def caa_missing(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    dns = domain.ok("domain_dns")
    if dns is not None and (dns.data.get("caa") or {}).get("found") is False:
        yield _draft(domain, "informational", "high", {"domain": domain.domain}, dns.id)


@domain_rule(
    "NS_NOT_REDUNDANT",
    title=N_("Name servers are not redundant"),
    summary=N_("The name servers of %(domain)s are not redundant: %(problems)s."),
    advice=N_("Use at least two name servers in different networks."),
    trigger="Fewer than two name servers (Medium), all servers in one network, or a server "
    "without an address (Low). One DNS operator alone is not a finding: the large providers "
    "are redundant by design.",
    severities=("low", "medium"),
    checks=("domain_dns",),
    labels={"problems": N_("Problems"), "count": N_("Name servers")},
)
def ns_not_redundant(domain: DomainFacts, settings: RuleSettings) -> Iterator[Draft]:
    dns = domain.ok("domain_dns")
    ns = (dns.data.get("ns") if dns else None) or {}
    problems = list(ns.get("problems", []))
    if dns is None or ns.get("found") is not True or not problems:
        return
    severity: Severity = "medium" if "too_few" in problems else "low"
    params = {"domain": domain.domain, "problems": problems, "count": ns.get("count")}
    yield _draft(domain, severity, "high", params, dns.id)
