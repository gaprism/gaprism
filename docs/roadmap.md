# Roadmap — MVP first

> Proposed 2026-10-04 · replaces `docs/implementation/*` and `docs/backlog.md` (archived by S0.1)
> Related: [design spec](superpowers/specs/2026-10-04-mvp-restart-design.md) · [checks catalogue](checks-catalog.md) · [code improvement plan](improvement-plan.md)

## 1. Goal and MVP

**Product.** One pane of glass for the *technical* side of vendor due diligence. Enter a domain → discover its hosts from Certificate Transparency (CT) → review every host → answer three questions: **Where is the data? Who processes it? How secure is the externally visible posture?** It replaces manual web-check.xyz sessions.

**The MVP is done when** an analyst can log in, enter `vendor.com`, and within minutes see:

- every CT-discovered host with DNS, IP/ASN/country, TLS, HTTP-header and open-port/CVE results;
- a domain-level view (email security, registration, security.txt);
- three plain-language summary cards (Where / Who / Secure) and a findings list;
- an export (JSON, CSV, printable HTML).

It runs with one PostgreSQL and two processes (web + worker). Users: 1–5 internal people; open source later; English UI first (strings stay translatable).

## 2. Principles (the useful part of the old 12 invariants)

1. **Typed outcomes.** `ok`, `no_data`, `unavailable` (no key / quota / disabled), `error`, `skipped` are different. Never show "clean" for "not checked". *(old INV-04)*
2. **Every fact has a subject, a source and a timestamp.** *(INV-03)*
3. **No over-claiming.** A CT name is not a live host; an IP observation is not a hostname attribution (shared infrastructure); an ASN owner is not a processor. *(INV-05)*
4. **One egress gate.** All target-facing traffic goes through `runner/` (public IPs only, IP-pinned, bounded). *(INV-06)*
5. **Everything is bounded:** hosts per scan, bytes, time, concurrency, retries.
6. **No side effects at import or startup.** *(INV-12)*
7. **A new check is one module + one test + one catalogue row.**
8. **Lean process.** Done = demo + tests + lint. Deep review only for egress, auth and SQL changes.

Deferred (kept in the archive, not deleted): RLS and per-report grants (INV-01/02), hashed immutable report snapshots (INV-07), lease-fencing queue (INV-08), retention clocks and backup replay (INV-09), DE/EN parity proof (INV-10), TPRM-transfer log (INV-11). They return as R5 stories only if a real need appears.

## 3. Releases (vertical slices — each one is demoable)

| Release | You can… | Epic | Stories |
|---|---|---|---|
| **R0 Reset** | start the app, log in, run the tests on your Postgres | E0 | 5 (S/M) |
| **R1 Walking skeleton** | enter a domain, watch hosts appear, see DNS / TLS / HTTP per host | E1 | 9 |
| **R2 Decision-ready** | read the Where / Who / Secure summary and findings; see ASN, ports/CVEs, email security | E2 | 8 |
| **R3 Share & report** | export a report, re-scan and diff, share with the team, run via docker compose | E3 | 5 |
| **R4 Depth** | screenshots, tech stack, third-party requests, takeover, TLS deep scan, reputation | E4 | pick by value |
| **R5 Open source & scale** | publish; PDF/DE report; SSO; retention; monitoring | E5 | later |

**Earliest visible results.** *Demo 1* (domain → hosts, no checks yet) after R0, S1.1–S1.3, a basic worker (S1.4a: single-threaded claim-and-run, discovery as the first task), basic progress polling (S1.5) and the hosts list of S1.9. *Demo 2* (live DNS/TLS/HTTP) after the rest of S1.4 (thread pool, limits, stale-lock requeue, cancel) and S1.6–S1.8. Everything after is additive.

**Status (2026-10-04, branch `mvp`).** Shipped: R0 (S0.1–S0.4), all of R1's stories (S1.1–S1.9: assessments, CT discovery, manual hosts, the threaded engine, progress, DNS, TLS and HTTP checks, the hosts table with a state filter and a host page with per-check facts and raw-JSON toggles). *Demo 1* and *Demo 2* are runnable with `flask run` plus `flask worker`. Next is R2 (IP intelligence and location, ports, email security, registration, rules, summary cards, finding acceptance). S0.5 (dependency diet) is still open.

**Sizes** are rough guesses to be recalibrated after R0/R1: **S** ≤ ½ day, **M** ≈ 1 day, **L** 2–3 days of focused, AI-assisted work. R0–R3 ≈ 27 days in total (S1.2 and S2.1 are now L, S2.6 is M); R4/R5 are not estimated.

## 4. Epics and stories

### E0 — Reset (R0)

**S0.1 Consolidate repo and docs** (S)
- Superseded docs (`docs/architecture.md`, `design/`, `implementation/`, `backlog.md`, `contribute.md`, `customizing.md`, `docs/ui/`, `.junie/plans/`) move to `docs/archive/2026-10-baseline-1/` with `git mv`. Nothing is deleted.
- `docs/README.md` ≤ 40 lines indexes only live docs. A ≤ 60-line `CLAUDE.md` (commands, conventions, links) is the only file an agent must read first.
- `.idea/` and `.junie/` stop being tracked; `.gitignore` is rewritten (the current one is copied from another project); the unused root-level `templates/` copy and the shadowed root `app.py` are removed (`assets/` is the Tailwind source and stays).
- Uncommitted work (auth rate limit, RLS migrations 0005/0006, `tests/security`, `tests/session_helpers.py`) is committed or archived on purpose, not lost.

**S0.2 Lean schema and DB setup** (M)
- New Alembic baseline: `assessment`, `scan`, `host`, `check_result`, `finding`, `finding_disposition`, `provider_cache` + Flask-Security tables + `auth_rate_limit`. Old migrations are archived.
- `flask db upgrade` works on an empty DB with the *application role only* (no superuser, no CREATEDB). A `DB_SCHEMA` setting (default `public`; this dev DB uses `due_diligence` because `public` is not writable there) is applied through `search_path`.
- Downgrade works; a test asserts models and migrations agree.

**S0.3 Test harness and CI** (M)
- `uv run pytest` is green with a single `TEST_DATABASE_URL`; each session creates and drops its own schema.
- Tests marked `live` (real network) are excluded by default; unit tests never touch the network. The 2 failing GeoIP tests are rewritten against a mocked provider.
- GitHub Actions: ruff, mypy (strict on `runner/` and `app/checks/`), pytest with a Postgres service.

**S0.4 App shell** (M)
- Login → assessments page renders (replaces the design-preview templates; the Tailwind tokens stay).
- Base layout with nav, flash messages, 403/404/500 pages; Flask-Babel wired for `en` (de-CH catalogs kept); CSP without `'unsafe-inline'` scripts; `/healthz`; `npm run build` documented; no CDN assets.
- Provider keys (`SHODAN_API_KEY`, `CTLOGS_API_KEY`, `CERTSPOTTER_TOKEN`) come from the environment only, are listed in `.env.example` without values, and a log filter redacts `key=`, `token=` and `Authorization` values.

**S0.5 Dependency diet** (S)
- Playwright, qrcode, bcrypt move to optional extras or are dropped; `dnspython`, `publicsuffixlist`, `maxminddb` are declared; lockfile refreshed; `pip-audit` clean or exceptions listed.

### E1 — Scan a domain (R1)

**S1.1 Create an assessment** (S)
- Accepts `vendor.com`; rejects URLs, IPs, wildcards, ports and *real* public suffixes. Today `co.kr`, `com.mx`, `blogspot.com` are accepted as scope; they must be refused.
- IDN shown in Unicode, stored as punycode; optional label; owner = current user; visibility `private`.
- Starting a scan while one is running for the same domain is refused with a link to it.

**S1.2 CT discovery from three sources** (L)
- `DiscoverySource` interface with three adapters:
  - **ctlogs.dev** — `GET /v1/hosts/{domain}`, `?after=` cursor, `Authorization: Bearer` key optional. Port of the existing adapter (verified against the live API on 2026-10-04); its rows also carry live DNS (`dns`, `a`), kept as a hint only.
  - **CertSpotter** — `GET /v1/issuances?domain=…&include_subdomains=true&expand=dns_names`, token optional, paged with `after`.
  - **crt.sh** — keyless; 30 s timeout, 3 retries with jittered backoff (it failed 4 of 4 probes on 2026-10-04).
- `CT_SOURCES` (order) and `CT_MODE=union|first`. Default **union**: every enabled source runs (in parallel, within `DISCOVERY_BUDGET_SECONDS`), names are merged and deduplicated, and each source's contribution is shown ("ctlogs 98 · CertSpotter 120 · crt.sh failed → 151 names"). A failing or slow source never fails the scan; the page says that discovery may be incomplete.
- Wildcards are kept as patterns, never as hosts; out-of-scope SANs are counted and excluded; host cap (default 200, configurable) with a visible "truncated" notice. Keys come from `CTLOGS_API_KEY` / `CERTSPOTTER_TOKEN`, are never logged and never shown.
- Each source outcome is stored (`ok` / `unavailable` / `error` + reason). If all sources fail, the scan continues with the apex (+ `www`) tagged `fallback` and a warning banner.
- Fixture tests per source; no live network in unit tests.

**S1.3 Manual hosts** (S)
- Add one or many hostnames (in scope only) and remove them; tagged `manual`; same checks as discovered hosts. This is the escape hatch when CT is down.

**S1.4 Execution engine** (L) — depends on S0.2
- `flask worker` claims `queued` `check_result` rows with `FOR UPDATE SKIP LOCKED` and runs registered checks in a thread pool (`WORKER_THREADS`, default 8; `--threads` overrides). A check starts only when the checks it `needs` for the same host are finished, so a dependent is never skipped because of timing.
- Limits: per-target concurrency (`PER_TARGET_CONCURRENCY`, default 4 tasks of one scan at once per worker process), host cap, stale-lock requeue after 10 min, cancel (queued checks are skipped, running ones finish and keep their results). Each check bounds its own network time through the runner's deadlines; a check that hangs anyway is recovered by the stale-lock requeue. One rate limiter per external provider ships with its first consumer (S2.2).
- Idempotent: unique `(scan, host, check)` means a retry cannot create a duplicate.
- Test: stale-lock requeue and fencing (a late result of the old worker is discarded); a 60-host scan with 8 threads finishes with every check run exactly once and never more than the per-target limit at the same time.

**S1.5 Progress UI** (M)
- The scan page polls via HTMX every 2 s while running: scan state, discovered/finished counts, per-host status chips. Polling stops at a terminal state.
- Shows a "no worker heartbeat" banner when queued work is not being picked up.

**S1.6 DNS check** (M)
- A / AAAA / CNAME chain / MX / NS / TXT / CAA via dnspython with timeouts and a configurable resolver.
- Every resolved IP is screened by the egress gate; private or reserved answers are recorded as `blocked` and never connected to. NXDOMAIN is `no_data`. Records keep their TTL.

**S1.7 TLS check** (S)
- Port `runner/tls.py`: SNI, chain, hostname, validity. Add key type/size, signature algorithm, chain length, wildcard flag, negotiated protocol/cipher.
- Typed failures (`expired`, `hostname_mismatch`, `untrusted`, `timeout`, `refused`). Verification is never disabled; the forensic read after a failure uses a separate, labelled, unverified context.

**S1.8 HTTP check** (M)
- `GET https://host/` (fallback `http://`) through the egress client: status, final URL and redirect chain (each hop screened), HTTP→HTTPS redirect, `Server` / `X-Powered-By`, security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), every `Set-Cookie` with Secure/HttpOnly/SameSite, timing. Body capped at 512 KB. The egress client must expose raw multi-value headers (today `Set-Cookie` collapses).

**S1.9 Hosts view** (M)
- Table: hostname, source, DNS, TLS, HTTP, findings count; SQL pagination (50/page), search, status filter. Host detail drawer with per-check results and a raw-JSON toggle. All target-supplied strings are escaped.

### E2 — Decision-ready (R2)

**S2.1 IP intelligence incl. city** (L)
- `GeoIPProvider` interface. Offline default: **DB-IP City Lite** (country, region, **city**, latitude/longitude) + **DB-IP ASN Lite**, both `.mmdb`, no account needed. `flask datasets update` downloads the official monthly files (`download.db-ip.com/free/dbip-{city,asn}-lite-YYYY-MM.mmdb.gz`, current then previous month) and falls back to the `wp-statistics/DbIP-City-lite` mirror (`cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz`); files are validated (opens as mmdb, database type, build date) and recorded with source and SHA-256. A keyless API (ipwho.is / ip-api) is an optional fallback; iptoasn is the ASN fallback.
- Result carries country (ISO), region, city, coordinates, ASN, organisation, database version/date. **Rules use the country only**; the city is shown for context because city accuracy for server IPs is poor. The CC BY 4.0 attribution link to db-ip.com appears in the UI and report footer.
- Typed statuses; reverse DNS; CDN/cloud hints from a small ASN list (used by the location rule).

**S2.2 Ports and CVEs** (M)
- `PORTS_PROVIDER=auto|shodan|internetdb`. With `SHODAN_API_KEY` set, **auto** uses the **Shodan host API** (`/shodan/host/{ip}`; port the existing adapter: typed outcomes, shared-infrastructure attribution); without a key it falls back to keyless **InternetDB** (non-commercial terms, documented). Both map to the same typed result.
- Per distinct IP, cached 24 h in `provider_cache`; Shodan calls go through a per-key rate limiter (default 1 request/s, configurable); 404 → `no_data`; CDN IPs mark results `ip_only`.
- The key travels in the query string, so URLs are redacted in logs and error messages. Fixtures are recorded from real responses (sanitised); the CVE parsing is verified against them — the old adapter reads the top-level `vulns` as a dict, which looks wrong for Shodan's list-of-IDs response.

**S2.3a Email security** (M) — domain level
- MX, SPF (qualifier, lookup count), DMARC (policy, pct, rua), DKIM (common selectors), MTA-STS, TLS-RPT, BIMI.

**S2.3b Domain registration** (S)
- RDAP via the IANA bootstrap file (direct to the registry): registrar, created/expires, status flags, nameservers, DNSSEC.

**S2.3c Misc domain checks** (S)
- security.txt (RFC 9116, expiry), HSTS preload status, CAA and NS diversity, public breach history (HIBP `breaches?domain=`).

**S2.4 Rules and findings** (M)
- ~25 rules with stable IDs ([catalogue §4](checks-catalog.md#4-initial-rule-set)); severity and confidence are separate; findings deduplicate, carry a stable fingerprint and link to their evidence rows. `docs/rules.md` is generated from code.
- Two owner-specified rules: **`LOCATION_OUTSIDE_EU_CH`** — High for a host with a public IP located outside the allowed area (EU-27 + EEA + CH, configurable); and **`PUBLIC_BREACH_HISTORY`** — Medium, **High if the breach is recent** (default ≤ 24 months, `BREACH_RECENT_MONTHS`). Details in [catalogue §4](checks-catalog.md#4-initial-rule-set).

**S2.5 Summary cards** (M)
- Where / Who / Secure + a coverage line ("148 names found; 112 live HTTPS; 8 unreachable; 22 excluded") and caveats ("endpoint location, not storage location"; "not a certification"). The *Where* card shows countries and cities, highlights hosts outside the allowed area and links to the matching findings. The *Secure* card counts open findings by severity plus an "accepted" chip. Fixture-tested.

**S2.6 Findings view and acceptance** (M)
- List and filter by severity, host, rule and status. Status per finding: `open`, **`accepted`**, `false_positive`.
- **Accepting a finding** requires a reason; an optional *review-by* date makes the acceptance expire (the finding becomes open again, flagged "acceptance expired"). Author and time are recorded on the disposition (and, once S3.5 lands, in the audit log); *reopen* is always possible.
- Acceptance belongs to the assessment, keyed by the finding fingerprint (`rule + subject`), so it **carries over to re-scans**; it does not change the evidence. Accepted findings leave the open counts and the summary severity totals but stay visible, and the report lists them in their own section with who, when, why and review date.

### E3 — Share and report (R3)

**S3.1 Export** (M) — JSON (full), CSV (hosts, findings), printable HTML report (summary, open findings, **accepted findings with reason/author/review date**, hosts incl. city, coverage, method, data-source attributions such as DB-IP).

**S3.2 History and re-scan** (M) — scan list per assessment, re-scan button, diff by fingerprint (new/removed hosts, new/resolved findings; accepted findings stay accepted).

**S3.3 Team model** (M) — visibility `private` / `team`; admin CLI (`flask users create|deactivate`); workspace/membership/grant tables removed; MFA optional by config (default on in production); login rate limit retained.

**S3.4 Deploy kit** (M) — `docker-compose.yml` (web, worker, db), `.env.example`, quickstart, reverse-proxy and backup notes.

**S3.5 Guardrails** (S) — per-user scan rate limit, host-cap enforcement, audit log (login, scan create/delete, export, finding accept/reopen).

### E4 — Depth (R4) — order by value ÷ effort

| ID | Story | Size |
|---|---|---|
| S4.1 | Subdomain-takeover detection (dangling CNAME + fingerprints) | M |
| S4.2 | Tech-stack and WAF/CDN fingerprinting (small own ruleset) | M |
| S4.3 | KEV / EPSS / NVD enrichment of observed CVEs | M |
| S4.4 | TLS protocols/ciphers (stdlib probes; optional external testssl/sslyze) | M |
| S4.5 | Reputation and blocklists (resolver-based; optional keyed providers) | M |
| S4.6 | Screenshots (Playwright, isolated runner, extras) | L |
| S4.7 | Third-party requests and cookies (browser network log → "who processes") | L |
| S4.8 | Optional cross-checks: Mozilla Observatory, SSL Labs apex deep dive | S |

### E5 — Open source and scale (R5)

| ID | Story |
|---|---|
| S5.1 | Licence decision, NOTICE file and data attributions (DB-IP, can-i-take-over-xyz) |
| S5.2 | CONTRIBUTING, SECURITY.md, issue templates, "how to add a check" guide |
| S5.3 | History hygiene, SBOM, dependency and image scanning |
| S5.4 | PDF and de-CH report; complete UI translation |
| S5.5 | SSO/OIDC and per-assessment grants (old access design as reference) |
| S5.6 | Simple retention (delete scans older than N days) and backup guidance |
| S5.7 | Scheduled re-scans and alerts (email / webhook) |
| S5.8 | TPRM export / API |

## 5. Definition of Done

- Demonstrable in the UI or CLI.
- Unit tests with fixtures; the default test run uses no live network.
- `ruff` and `mypy` pass (strict on `runner/` and `app/checks/`).
- Catalogue status updated when a check ships.
- Egress, auth or SQL changes carry a short review note in the PR.

## 6. Cut lines and risks

- **If time is short, drop:** scan diff (S3.2), DKIM selector probing, HIBP, the audit log.
- **crt.sh is unreliable** → three CT sources merged, retry/backoff, manual hosts, caching.
- **Free-API terms change** (InternetDB and ip-api are non-commercial) → provider interfaces, `unavailable` status, config switches, terms documented in the catalogue.
- **Scanning third-party infrastructure:** only low-impact requests (DNS, one TLS handshake, one GET); an identifying User-Agent; a blocklist setting; a "assess only what you are allowed to" notice.
- **Copyleft data/tools** (sslyze AGPL, webappanalyzer GPL) stay out of the core until the licence is chosen (S5.1).

## 7. Where the old plan went

| Old milestone | New home |
|---|---|
| M0 Foundation | E0 (kept: factory, config, tooling) |
| M1 Identity, grants, RLS | S3.3 (simple), S5.5 (SSO/grants later) |
| M2 Durable jobs, quota ledger | S1.4 (task table + worker, no leases/ledger) |
| M3 Discovery + network gate | S1.1–S1.3 (gate kept as is) |
| M4 Verification + enrichment | S1.6–S1.8, S2.1–S2.3, E4 |
| M5 Workspace UI + annotations | S1.5, S1.9, S2.5, S2.6 |
| M6 Evidence + bilingual reports | S3.1 now, S5.4 later |
| M7 Retention + operations | S3.4, S5.6 |
