# Checks catalogue — what we check, and with which free data

> Proposed 2026-10-04. Built from a review of all 38 web-check handlers (`Lissy93/web-check`, MIT) and a live probe of the candidate free sources on 2026-10-04. Roadmap stories reference the IDs below.
> **Answers:** **W** = Where is the data? · **P** = Who processes it? · **S** = How secure is the external posture?

## 1. Checks we will build

**Host level** (run for every host)

| ID | Check | Answers | Source (free, no account) | Leaves our network? | Size | Rel. | web-check |
|---|---|---|---|---|---|---|---|
| C01 | DNS: A/AAAA/CNAME chain, MX, NS, TXT, CAA | W P | dnspython → configured resolver | hostname → resolver | M | R1 | dns, txt-records, dns-server |
| C02 | TLS certificate and handshake (chain, SAN, validity, key, protocol) | S P | stdlib `ssl` + `cryptography` (existing prober) | direct to target | S | R1 | ssl, tls-connection |
| C03 | HTTP: status, redirects, security headers, cookie flags, server banner | S P | egress client (existing) | direct to target | M | R1 | headers, http-security, cookies, redirects, status, hsts |
| C04 | IP → **city, region, country**, ASN, organisation, CDN/cloud hint | W P | DB-IP City Lite + ASN Lite (local files; official download, `wp-statistics/DbIP-City-lite` mirror as fallback); iptoasn; API fallback | local; API fallback sends the IP | L | R2 | location, get-ip |
| C05 | Observed open ports, services, CPEs, CVE IDs | S | **Shodan host API (owner's key)** → InternetDB (keyless fallback) | IP → Shodan | M | R2 | shodan, ports |
| C06 | Reverse DNS and associated hostnames | P | PTR (dnspython); InternetDB `hostnames` | – | S | R2 | – |
| C07 | CDN / WAF detection (hint in S2.1; WAF fingerprinting in S4.2) | P S | ASN + headers + CNAME patterns | none | S | R2/R4 | firewall |
| C08 | Subdomain takeover (dangling CNAME) | S | DNS + `can-i-take-over-xyz` fingerprints (CC-BY-4.0) | direct to target | M | R4 | – |
| C09 | Tech-stack fingerprint | P S | headers, cookies, meta, script URLs; small own ruleset | direct | M | R4 | tech-stack |
| C10 | Screenshot (evidence) | – | Playwright in an isolated runner | direct | L | R4 | screenshot |
| C11 | Third-party requests and cookies | P | Playwright network log | direct | L | R4 | trackers |
| C12 | TLS protocol / cipher support | S | stdlib handshake probes; optional external testssl/sslyze | direct | M | R4 | tls-labs |
| C13 | Reputation / blocklists | S | resolver-based block detection; optional keyed providers | hostname → resolver/provider | M | R4 | threats, block-lists |
| C14 | CVE enrichment: CISA KEV, EPSS, NVD | S | KEV JSON, FIRST EPSS, NVD | CVE IDs | S | R4 | – |

**Shipped:**
- **C01 DNS** (S1.6, 2026-10-04): A, AAAA, the explicit CNAME chain (with a `dangling_cname` flag when the last target does not exist), MX, NS, TXT and CAA, each with its TTL, asked of `EGRESS_DNS_RESOLVERS` (default 1.1.1.1 and 8.8.8.8; `system` uses the operating system's resolver). Every address is screened with the egress gate's rules: non-public answers are listed under `blocked` with a reason (private, loopback, link-local, …) and never reach a check that connects; `addresses` holds the usable public ones. NXDOMAIN is `no_data`; a name that exists but has no records is `no_data` (`no_records`); a failing record type is listed under `errors` (timeout, servfail, …), and an unreachable resolver ends the check after two questions. Bounds: 50 records per type, 2000 characters per TXT value.

**Domain level** (run once per scan)

| ID | Check | Answers | Source | Leaves our network? | Size | Rel. | web-check |
|---|---|---|---|---|---|---|---|
| C20 | Email security: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI | S P | dnspython + HTTPS | direct | M | R2 | mail-config |
| C21 | Registration: registrar, created/expires, status locks, nameservers | S P | RDAP via IANA bootstrap (direct to registry) | domain → registry | S | R2 | whois |
| C22 | DNSSEC | S | dnspython | – | S | R2 | dnssec |
| C23 | security.txt (RFC 9116) | S | HTTPS GET | direct | S | R2 | security-txt |
| C24 | Public breach history | S | HIBP `breaches?domain=` | domain → HIBP | S | R2 | breaches |
| C25 | HSTS preload status | S | hstspreload.org API | domain → API | S | R2 | hsts |
| C26 | CT inventory facts (issuers, first/last seen, wildcard count) | P | from discovery | – | S | R1 | subdomains |
| C27 | Independent header grade | S | Mozilla Observatory API v2 | host → Mozilla | S | R4 | – |
| C28 | SSL Labs deep dive (apex, on demand) | S | SSL Labs API | host → Qualys | S | R4 | tls-labs |

## 2. web-check handlers we do not adopt

| Handler | Decision |
|---|---|
| carbon, quality, social-tags, social-presence, linked-pages, sitemap, robots-txt, trace-route | **Skip** — no bearing on where/who/security; trace-route is also active probing |
| rank, archives | **Later** (R5, context only) |
| get-ip, location, ports | **Merged** into C04 / C05 |
| cookies, redirects, status, hsts, http-security, headers | **Merged** into C03 |
| dns, txt-records, dns-server | **Merged** into C01 / C20 |
| screenshot, tech-stack, trackers, firewall, threats, block-lists, tls-labs | **Adopted later** (R2–R4, see §1) |

## 3. Free sources — verified 2026-10-04

| Source | Used for | Result of probe | Limits / terms to respect |
|---|---|---|---|
| **crt.sh** (`/?q=%25.domain&output=json`) | CT discovery | **502 ×3, 45 s timeout ×1** | Free, community-run, frequently overloaded → retry + fallback + manual hosts |
| **ctlogs.dev** (`/v1/hosts/{domain}`) | CT discovery | 200 without a key; envelope `hosts, has_next, next_cursor, duration_ms, history_window_days`; rows carry `dns` and `a` (live DNS) | See [CT sources](#ct-discovery-sources-s12); matches the existing adapter (`?after=` cursor) |
| **CertSpotter** v1 (`/v1/issuances`) | CT discovery | 200 without a key; header `x-ratelimit-limit: 10` | Docs promise only "a limited number" of unauthenticated queries; "may be restricted at any time"; optional token |
| **Shodan host API** (`/shodan/host/{ip}?key=`) | C05 | *Not probed* — the key stays out of the repo and chat | Owner has a key. Per Shodan's docs host lookups do not consume query credits; key travels in the query string → redact in logs; assume ~1 req/s per key |
| **Shodan InternetDB** | C05 fallback | 200 without a key; fields `cpes, hostnames, ip, ports, tags, vulns`; cached 5 days | **Free for non-commercial use only**; updated weekly; no banners/CVSS → used only when no Shodan key is set |
| **RDAP** (IANA bootstrap `dns.json`, rdap.org) | C21 | 200; registry data incl. `secureDNS`, nameservers, events | Query the registry directly via the bootstrap file; cache the file |
| **DB-IP Lite** `.mmdb` (country 4 MB, ASN 5 MB, **city 60 MB**) | C04 | `download.db-ip.com/free/dbip-*-lite-YYYY-MM.mmdb.gz` → 200 (`db-ip.com` itself did not resolve from this network) | **CC BY 4.0** — attribution link to db-ip.com required; monthly refresh; no account (MaxMind GeoLite2 needs a licence key) |
| **`wp-statistics/DbIP-City-lite`** mirror | C04 city fallback | Repo updated monthly by CI (v1.0.18 on 2026-10-01); `dbip-city-lite.mmdb.gz` is the same 60,193,321-byte file as DB-IP's 2026-10 release; stable URL `cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz` | Repo licence is MIT, **the data stays CC BY 4.0**; third-party mirror → validate the file, prefer the official URL first |
| **iptoasn.com** TSV | ASN fallback | 9 MB, updated hourly | **PDDL (public domain)**; the public API was retired in 2020 → use the file; country = AS registration, not geolocation |
| **ipwho.is**, **ip-api.com**, **ipapi.is** | C04 API fallback | all 200 without a key | ip-api: HTTP only, 45 req/min, non-commercial; use only as a fallback and only when the user enables it |
| **Mozilla Observatory** v2 (`POST /api/v2/scan?host=`) | C27 | 200 without a key; grade + score | Independent cross-check; sends the host |
| **SSL Labs** v3/v4 `/info` | C28 | 200; `maxAssessments: 7` | Slow (minutes/host), terms limit bulk use → on-demand only |
| **HIBP** `breaches?domain=` | C24 | 200 without a key | Needs a User-Agent; 5-min cache; context only |
| **CISA KEV** JSON / **EPSS** / **NVD** 2.0 | C14 | 200 (KEV 195 KB, updated 2026-10-02) | NVD ≈ 5 req/30 s without a key → cache locally |
| **hstspreload.org** | C25 | 200 | – |
| **Tranco**, **Wayback availability** | context | 200 | Low value |
| **URLhaus** (abuse.ch) | C13 | **401 — now needs an Auth-Key** | Free account; optional adapter only |
| Cloudflare DoH, Quad9 DoH | – | 400 / timeout | Not used: dnspython against a configured resolver is simpler |

### CT discovery sources (S1.2)

Default `CT_MODE=union`: every enabled source runs (in parallel, within `DISCOVERY_BUDGET_SECONDS`), names are merged and deduplicated, and the UI shows what each source contributed. A failing or slow source never fails the scan; the UI then warns that discovery may be incomplete.

| Source | Endpoint | Auth | Limits seen / documented | History | Notes |
|---|---|---|---|---|---|
| **ctlogs.dev** | `GET /v1/hosts/{domain}`, `?after=<next_cursor>` | none or `Bearer` key | Anonymous: 100 requests/h (UTC hours), 1 in flight, first 10 pages (1,000 rows). Free key: non-commercial. Paid plans: commercial use | Current + expired ≤ 90 days (`history_window_days`); full archive on Pro | One row per host: cert count, first/last seen, `last_not_after`, live DNS (`dns`, `a`); wildcard rows included; 1 credit per page |
| **CertSpotter** | `GET /v1/issuances?domain=…&include_subdomains=true&expand=dns_names` | none or token | Unauthenticated: "a limited number" per hour (header showed `x-ratelimit-limit: 10`); may change without notice | All issuances it has indexed | One row per certificate → deduplicate names; page with `after` |
| **crt.sh** | `GET /?q=%25.domain&output=json` | none | None documented; frequently overloaded | All logs | 502 / timeout on 4 of 4 probes → retries with jittered backoff |

## 4. Initial rule set

Findings come from versioned rules. Severity and confidence are separate; provider data keeps its own severity next to ours.

| Rule | Trigger | Severity |
|---|---|---|
| `TLS_INVALID` | expired / untrusted chain → High; hostname mismatch → Medium | High/Med |
| `TLS_EXPIRES_SOON` | < 30 days (< 7 days → Medium) | Low/Med |
| `TLS_WEAK_KEY` / `TLS_WEAK_SIGNATURE` | RSA < 2048, SHA-1/MD5 | High |
| `TLS_LEGACY_PROTOCOL` | TLS 1.0/1.1 accepted (R4) | Medium |
| `NO_HTTPS` / `HTTP_NO_HTTPS_REDIRECT` | host serves only HTTP / no redirect | High / Medium |
| `HSTS_MISSING` / `HSTS_WEAK` | header absent / max-age < 6 months | Low / Info |
| `CSP_MISSING`, `XCTO_MISSING`, `FRAME_PROTECTION_MISSING` | header absent on an HTML response | Low |
| `COOKIE_INSECURE` | session-like cookie without Secure/HttpOnly | Medium |
| `SERVER_VERSION_DISCLOSED` | `Server`/`X-Powered-By` shows a version | Info |
| `SPF_MISSING` / `SPF_PERMISSIVE` | no SPF / `+all` or `?all` | Medium / High |
| `DMARC_MISSING` / `DMARC_POLICY_NONE` | no DMARC / `p=none` | Medium / Low |
| `DNSSEC_NOT_ENABLED`, `MTA_STS_MISSING` | absent | Info |
| `RISKY_PORT_EXPOSED` | 21, 22, 23, 445, 3389, 3306, 5432, 6379, 9200, 11211, 27017 observed | Medium/High |
| `CVE_OBSERVED` | CVE IDs from InternetDB; `ip_only` on shared infrastructure | Info (R4: by KEV/EPSS/CVSS) |
| `KEV_LISTED_CVE` | CVE in CISA KEV (R4) | High |
| `DANGLING_CNAME` | takeover fingerprint matches (R4) | High |
| `DOMAIN_EXPIRES_SOON` / `DOMAIN_RECENTLY_REGISTERED` | < 30 days / < 90 days old | Medium / Info |
| `LOCATION_OUTSIDE_EU_CH` | a public IP of the host is located outside the allowed area (EU-27 + EEA + CH) | **High**; Medium with low confidence for CDN/anycast IPs (edge only) |
| `PUBLIC_BREACH_HISTORY` | HIBP lists a breach of the vendor's own service (fabricated and spam-list entries ignored) | **Medium; High if the breach date is within 24 months** (`BREACH_RECENT_MONTHS`) |
| `SECURITY_TXT_MISSING` | no RFC 9116 file | Info |
| `COLLECTION_INCOMPLETE` | a source was `unavailable` / `error` | Coverage notice, not a severity |

**Data-location policy (rule `LOCATION_OUTSIDE_EU_CH`).**
- Allowed area = EU-27 + EEA (IS, LI, NO) + CH, configurable (`DATA_LOCATION_ALLOWED`, ISO codes) so adequacy countries such as GB or JP can be added.
- The rule uses the *country* from DB-IP; the city is context only (accuracy for server IPs is poor).
- One finding per host. It fires if *any* resolved public IP is outside the area and lists the IPs and countries.
- CDN/anycast IPs (ASN hint list) show the edge, not the data centre, so they raise Medium with low confidence instead of High — otherwise every Cloudflare- or CloudFront-fronted vendor would be a High finding.
- No location data (database missing, IP not in the database) is a coverage notice, never "clean".
- The finding can be accepted with a reason and a review date ([S2.6](roadmap.md)).

## 5. Licensing notes for the open-source release

| Item | Licence | Consequence |
|---|---|---|
| web-check | MIT | Ideas and code may be reused with the notice |
| `sslyze` | **AGPL-3.0** | Do not import into the core unless the project is AGPL; optional external CLI only |
| `enthec/webappanalyzer` data | **GPL-3.0** | Do not bundle; write our own small ruleset or let users download it |
| `can-i-take-over-xyz` fingerprints | CC-BY-4.0 | Bundle with attribution |
| DB-IP City / ASN Lite (incl. the `wp-statistics` mirror) | CC BY 4.0 (the mirror's repo is MIT; the data is not) | Attribution link to db-ip.com in the UI/report footer; do not commit the `.mmdb` files |
| `publicsuffixlist` | MPL-2.0 | Fine as a dependency |
| `dnspython` / `maxminddb` | ISC / Apache-2.0 | Fine |

Decide the project licence early (S5.1): it determines what may be bundled.

## 6. How to add a check

A check is one module in `app/checks/` that returns a typed outcome; the registry, scheduler, storage, rules and UI pick it up.

```python
class Check(Protocol):
    key: str                                  # "tls"
    scope: Literal["host", "domain"]
    needs: tuple[str, ...]                    # e.g. ("dns",): runs only if those are ok
    def run(self, ctx: CheckContext) -> CheckOutcome: ...

# CheckOutcome(status="ok|no_data|unavailable|error|skipped", reason_code, data: dict, findings: list[FindingDraft])
```

Checklist: module + unit test with fixtures (no network) + catalogue row + (if it can fail noisily) a rule in `app/checks/rules/`.
