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

**Status (2026-10-06, branch `mvp`).** Shipped: all of R0 (S0.1–S0.5), all of R1 (S1.1–S1.9: assessments, CT discovery, manual hosts, the threaded engine, progress, DNS, TLS and HTTP checks, the hosts table and the host page), all of R2 (S2.1–S2.6: IP location, ports and CVEs, email security, registration, the domain checks, 34 rules and findings, the Where / Who / Secure summary and the findings view with acceptance) and all of R3 (S3.1–S3.5: export and report, history and diff, the team model, the docker compose kit, guardrails and the audit log). *Demo 1* and *Demo 2* are runnable with `flask run` plus `flask worker`, and the stack also runs with `docker compose up`. Next is R4 (depth), picked by value; the backlog below holds what was decided not to build yet.

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
- *Built (2026-10-06):* what the code imports is declared and nothing else. **Dropped:** `pydantic` (nothing imported it: five packages gone with it), `pytest-cov` (nothing used coverage) and the explicit `jinja2` (Flask requires it); `pyotp` moved to the dev group (one test makes authenticator codes with it); bcrypt and Playwright were already out (Playwright is the `screenshots` extra, for S4.6). **Declared** because the code imports them: `click`, `Flask-Login`, `Werkzeug`, `WTForms`, and `netaddr` for the tests. **Kept on purpose:** `qrcode` (Flask-Security refuses to start with two-factor on and no qrcode, so it is not optional while MFA is on by default), `argon2-cffi` (the configured password hash), `psycopg` (the driver SQLAlchemy loads) and `python-dotenv` (`flask` reads `.env` with it). `tests/test_dependencies.py` keeps it that way: every third-party import of `app/`, `runner/` and `migrations/` must be a declared runtime dependency, tests and scripts must be covered by the runtime or dev lists, and a runtime dependency that nothing imports needs a reason in that file. The unused mypy sections (`playwright`, `pyotp`, `qrcode`) are gone. The lock went from 90 to 84 packages (41 in an installation of the application) and was refreshed (mypy 2.4, ruff 0.16.10, SQLAlchemy 2.1.3, markupsafe 3.0.4 and a few small ones); **`pip-audit` reports no known vulnerabilities**. Verified: `uv sync --locked` into a brand-new environment installs and passes the tests there; every locked package except `flask-principal` (pure Python, built in the image's build stage as before) has a ready-made wheel for Python 3.11 and 3.13 on Linux x86-64 and arm64. **Licences** of those 41 packages, for the open-source release: BSD 17, MIT 13, Apache-2.0 3, MPL-2.0 2 (`certifi`, `publicsuffixlist`), LGPL-3.0 2 (`psycopg`, `psycopg-binary`: used as a library, unmodified), ISC, PSF and Unlicense one each; no GPL or AGPL (the SBOM and the image scan stay with S5.3). Lesson: on Windows `uv sync` cannot replace a compiled package that a running process has loaded (`markupsafe` under the worker) and the failed run left `.venv` half-installed; it was repaired, the refresh of the two packages the worker had loaded waited until the worker was stopped, and CLAUDE.md says to stop the worker and the web first.
- *Left for later:* the SBOM and the image scan (S5.3); the lock is not refreshed on a schedule (no Dependabot or Renovate yet).

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
- *Built (2026-10-04):* everything above except the optional keyless API fallback and the iptoasn ASN fallback, which stay unbuilt until someone needs a first-run experience without the 65 MB download (without the databases the check says `unavailable` and names the command). The CDN hint also reads the CNAME chain and reverse DNS, because the AS number alone cannot tell CloudFront from EC2 and the ASN database lacks some CDN ranges (e.g. Edgecast's 93.184.216.0/24).

**S2.2 Ports and CVEs** (M)
- `PORTS_PROVIDER=auto|shodan|internetdb`. With `SHODAN_API_KEY` set, **auto** uses the **Shodan host API** (`/shodan/host/{ip}`; port the existing adapter: typed outcomes, shared-infrastructure attribution); without a key it falls back to keyless **InternetDB** (non-commercial terms, documented). Both map to the same typed result.
- Per distinct IP, cached 24 h in `provider_cache`; Shodan calls go through a per-key rate limiter (default 1 request/s, configurable); 404 → `no_data`; CDN IPs mark results `ip_only`.
- The key travels in the query string, so URLs are redacted in logs and error messages. Fixtures are recorded from real responses (sanitised); the CVE parsing is verified against them — the old adapter reads the top-level `vulns` as a dict, which looks wrong for Shodan's list-of-IDs response.
- *Built (2026-10-04):* everything above, plus the `after` ordering (a check waits for another without needing it to succeed), the shared per-provider rate limiter, the database cache with a 30-day sweep and the log redaction filter. The InternetDB fixture is a recorded real answer and the keyless chain DNS → ports was run live. **Still open:** a raw Shodan host response recorded as a fixture (with the owner's OK; the parser follows the documented shape and parsed one real answer correctly in a verification scan); the old adapter and its rule were removed, the rebuilt rules come with S2.4.

**S2.3a Email security** (M) — domain level
- MX, SPF (qualifier, lookup count), DMARC (policy, pct, rua), DKIM (common selectors), MTA-STS, TLS-RPT, BIMI.
- *Built (2026-10-05):* all of it, plus the domain-level plumbing the later checks reuse: a "Domain checks" panel on the assessment page (one line per check) and a domain page with the facts of each (same section layout as the host page; a check's detail template is optional). Details and the live findings are in the catalogue (C20).

**S2.3b Domain registration** (S)
- RDAP via the IANA bootstrap file (direct to the registry): registrar, created/expires, status flags, nameservers, DNSSEC.
- *Built (2026-10-05):* all of it, plus a supplemental table for the ccTLDs IANA's file lacks (`.ch`, `.li`, `.de`, `.io`), the registrable-domain lookup, and `EXTERNAL_DOMAIN_LOOKUPS` to switch each third-party lookup of the domain off. `.ch` publishes no dates, so a Swiss domain's expiry cannot be read from RDAP at all (catalogue C21).

**S2.3c Misc domain checks** (S)
- security.txt (RFC 9116, expiry), HSTS preload status, CAA and NS diversity, public breach history (HIBP `breaches?domain=`).
- *Built (2026-10-05):* four checks (`security_txt`, `hsts_preload`, `domain_dns` for CAA and name servers, `breaches`), each with its own summary line and section on the domain page. The roadmap's DNSSEC item is part of the registration check. Details, and what the live runs taught (lower-case `z` in expiry dates, one DNS operator is a note not a failure), are in the catalogue.

**S2.4 Rules and findings** (M)
- ~25 rules with stable IDs ([catalogue §4](checks-catalog.md#4-initial-rule-set)); severity and confidence are separate; findings deduplicate, carry a stable fingerprint and link to their evidence rows. `docs/rules.md` is generated from code.
- Two owner-specified rules: **`LOCATION_OUTSIDE_EU_CH`** — High for a host with a public IP located outside the allowed area (EU-27 + EEA + CH, configurable); and **`PUBLIC_BREACH_HISTORY`** — Medium, **High if the breach is recent** (default ≤ 24 months, `BREACH_RECENT_MONTHS`). Details in [catalogue §4](checks-catalog.md#4-initial-rule-set).
- *Built (2026-10-05):* 34 rules in `app/rules/` (16 host, 2 address, 16 domain), pure functions over stored results, listed in the generated [rules.md](rules.md) (`uv run python -m app.rules.docs`; a test keeps it current). `fingerprint = sha256(rule | subject)`; findings are deduplicated, capped at 5,000 per scan and point at their evidence rows. They are evaluated when a scan finishes — inside a savepoint, so a crashing rule or a database error costs the findings, never the scan — and again with `flask findings evaluate`. The UI: a findings panel on the assessment page (counts by severity, the five most serious), a *Findings* column in the hosts table, a section on every host page (its own findings, then those about the addresses it resolves to) and a findings page with severity and rule filters. A scan without findings says that the rules only judge what the checks collected; a scan that was cancelled, or still runs, says that nothing was evaluated. Building it exposed a bug in the email check (a second DMARC record's `multiple_records` problem was overwritten by the parser's own problems), now fixed with a regression test. The old `app/service/checks/` (TLS evaluation, Web Risk adapter) is removed; Web Risk returns in R4 as a check plus a rule.
- *Delivered by S2.6:* filtering by host and by status, and the acceptance workflow.

**S2.5 Summary cards** (M)
- Where / Who / Secure + a coverage line ("148 names found; 112 live HTTPS; 8 unreachable; 22 excluded") and caveats ("endpoint location, not storage location"; "not a certification"). The *Where* card shows countries and cities, highlights hosts outside the allowed area and links to the matching findings. The *Secure* card counts open findings by severity plus an "accepted" chip. Fixture-tested.
- *Built (2026-10-05):* a coverage band and the three cards at the top of every finished scan (cancelled and failed ones too, showing their gaps; nothing while a scan runs), computed live from `check_result` and `finding` by `app/service/summary.py`. **Coverage:** certificate names seen; hosts reviewed (fully checked, with gaps); answering on HTTPS (and on plain HTTP only); not reachable (no public address, no web server); not reviewed (outside the domain, wildcard patterns, over the limit). Every host falls in exactly one web state, and it is *fully checked* only if none of its checks failed, was unavailable, did not finish or was cancelled. **Where:** hosts per country with the ones outside the allowed area first, flagged and linked to the matching findings; the busiest cities; hosts behind a CDN or anycast network counted apart as "edge, not data location"; hosts that could not be located counted with the reason. The allowed area is `DATA_LOCATION_ALLOWED`, and a test checks that the card and the rule agree about who is outside. **Who:** the networks behind the addresses (CDN, cloud or hosting, AS numbers), DNS operators, mail providers (recognised platforms by name, other MX hosts by registrable domain), services the SPF record allows to send, the registrar; a check that gave no answer says "not determined" and why, never "none". **Secure:** open findings by severity (each links to its filtered list), the three most serious rules, "N of M hosts fully checked" with a link to the hosts with failed checks, and chips for accepted and false-positive findings, counted from `finding_disposition` by fingerprint (an acceptance whose review date has passed counts as open again). Each card ends with what it does not say: an address is announced somewhere, not stored there; providers seen from outside are not the legal processors; this is not a certification.
- *Left for later:* the third-party requests of the *Who* card (R4).

**S2.6 Findings view and acceptance** (M)
- List and filter by severity, host, rule and status. Status per finding: `open`, **`accepted`**, `false_positive`.
- **Accepting a finding** requires a reason; an optional *review-by* date makes the acceptance expire (the finding becomes open again, flagged "acceptance expired"). Author and time are recorded on the disposition (and, once S3.5 lands, in the audit log); *reopen* is always possible.
- Acceptance belongs to the assessment, keyed by the finding fingerprint (`rule + subject`), so it **carries over to re-scans**; it does not change the evidence. Accepted findings leave the open counts and the summary severity totals but stay visible, and the report lists them in their own section with who, when, why and review date.
- *Built (2026-10-05):* the findings page lists the **open** findings by default, with tabs for *Accepted*, *False positive* and *All* (each with its count) and filters for severity, rule and host (a host's own findings and those about the addresses it resolves to). Every finding shows its status and, when somebody decided, who, when, why and until when. Decisions are made on the findings page and on the host page with one form: accept or false positive, a reason is required, a review-by date is optional and only for acceptances, and *Reopen* takes a decision back. A decision belongs to the assessment and is keyed by the fingerprint, so it carries over to re-scans (a live re-scan showed the earlier decisions); an acceptance whose review date has passed is open again and flagged "Acceptance expired", its reason still readable; a false positive does not expire. The assessment page (the findings panel, the hosts table) and the Secure card count open findings only and say how many were decided, linking to those lists. A decision is changed in place: the replaced state goes into `history` (the last 20), and reopening deletes the row, so every change is also written to the `app.audit` log (who, what, which finding, never the reason) until the audit log of S3.5. Anyone who can open the assessment can decide; the forms are CSRF-protected and return to the page they came from through checked values, never a URL taken from the request.
- *Left for later:* nothing of this story: the audit log came with S3.5 and the report section for accepted findings with S3.1.

### E3 — Share and report (R3)

**S3.1 Export** (M) — JSON (full), CSV (hosts, findings), printable HTML report (summary, open findings, **accepted findings with reason/author/review date**, hosts incl. city, coverage, method, data-source attributions such as DB-IP).
- *Built (2026-10-05):* a *Report and export* panel on every finished scan (cancelled ones too) with four downloads, all made from one `ExportData` that `app/service/export.py` reads from the stored facts in a fixed order (hosts by name, checks in display order, findings open first and most serious first), so two exports of the same scan differ only in their timestamp. **JSON** is versioned (`format.version`) and holds everything: the summary cards, the discovery record, every check result with status, reason, source, time and its stored data, every finding with its evidence ids and the team's decision, and the data sources used. **Hosts CSV** (one row per host: addresses, countries, cities, networks, CDN edge, ports, CVEs, TLS state and expiry, HTTP, open findings, gaps) and **findings CSV** (severity, status, rule, host, evidence, who decided, when, why, review date, fingerprint) are made for spreadsheets: UTF-8 with a byte order mark, text that could be read as a formula gets an apostrophe, edge addresses are not counted as places. The **report** is one printable page (A4, the browser saves it as PDF) with seven sections: summary (the three cards and the coverage), open findings by severity with their evidence, the findings the team decided about (reason, who, when, review date), hosts with cities, the domain's own checks, method and limits (discovery sources and what each answered, the host limit, what each check does, the rule set), and the data sources with their terms (DB-IP's "CC BY 4.0" line among them). It carries the same caveats as the cards (a location is not a storage place; no finding is not a clean bill of health; not a certification), loads no inline script or style, and escapes everything that came from the network or from people. Access is that of the assessment (404 for strangers), responses are `no-store`, and each export leaves a line in the `app.audit` log. The format is written down in [export-format.md](export-format.md) and a test keeps the document and the code in step. A live scan of badssl.com (9,977 names in the certificate logs, 12 reviewed) exposed a coverage bug from S2.5: *over the limit* counted only the hosts the scan plan dropped, not the names discovery itself had already cut, so the page said "0" for 9,964 unreviewed names; one function (`hosts_over_limit`) now adds both and feeds the coverage band, the scan panel's notice and the report.
- *Left for later:* a PDF made on the server and the de-CH report (S5.4), exporting an older scan (S3.2).

**S3.2 History and re-scan** (M) — scan list per assessment, re-scan button, diff by fingerprint (new/removed hosts, new/resolved findings; accepted findings stay accepted).
- *Built (2026-10-06):* a **Scan history** page (`/assessments/<id>/scans`, linked from the assessment page): every scan, newest first, with its status, who started it, how long it took, its hosts, the findings it stored (and how many were high or critical) and the report, JSON and CSV files of that scan, since the export routes now take `?scan=` for any scan that has ended (the report of an older scan shows today's decisions: they belong to the assessment). A **What changed** page (`/assessments/<id>/compare`, also linked from the scan panel) compares two ended scans, by default the two newest that ran to the end; a cancelled or failed scan is compared only when chosen. Hosts are matched by name and findings by fingerprint: *new*, *resolved*, *changed severity*, *not re-checked*, and the number that stayed the same, of which so many were accepted or marked as false positives (decisions carry over from scan to scan). **Resolved means the checks the finding rested on ran again and answered and the rule no longer fires**; when one of them failed, was unavailable or skipped, or the host is not in the newer scan, the finding is *not re-checked* and says why ("the HTTP check of beta… failed in the newer scan: timeout"): not looked at is not fixed. Hosts missing from the newer scan are *no longer found*, not *gone*, and the page says when it cannot know: a certificate source failed or was cut short or hosts were over the limit (in either scan), a scan ended with gaps, the scans were judged by different rule sets, findings were cut by the per-scan limit, a scan was never evaluated (then only the hosts are compared). Lists are capped at 100 per group with complete counts; everything is read-only and has the access rules of the assessment (a scan of another assessment is a 404). The *over the limit* count (S2.5 fix) is what lets the page say that. Verified live with two real scans of badssl.com and two hosts added by hand between them (two new hosts, twelve new findings, nineteen unchanged, both discovery gaps noted, reports of both scans, no overflow at 375 px); `tests/test_history.py` builds a scan and a re-scan that differ in every way the comparison tells apart (resolved, new, changed, a failed check, a vanished host, an unchanged and an accepted finding).
- *Left for later:* what the checks collected beyond hosts and findings (addresses, ports, certificates, TLS details), the comparison inside the report and the exports, scheduled re-scans.

**S3.3 Team model** (M) — visibility `private` / `team`; admin CLI (`flask users create|deactivate`); workspace/membership/grant tables removed; MFA optional by config (default on in production); login rate limit retained.
- *Built (2026-10-06):* most of the model was there since the restart: no workspace, membership or grant tables, assessments private or shared with the team when they are created, owner and administrators always allowed in, MFA by `REQUIRE_MFA`, the sign-in limit. What S3.3 added is what a team needs to live with it. **Sharing can be changed**: the owner or an administrator uses *Share with the team* / *Make private* on the assessment page; a colleague who can open a shared assessment may scan it, add hosts and decide about its findings but not change who sees it (403); somebody who cannot open it gets a 404 as before; a domain can be shared once (a second one is refused with a message). The list and the assessment page say whose each assessment is. **Accounts** are run with `flask users`: `create [--admin]`, `list`, `set-password`, `deactivate`, `activate`, `grant-admin`, `revoke-admin`, `reset-mfa` (next to the existing `create-admin`), because there is no mail to recover a password or a lost authenticator by: a new password or a reset ends the person's sessions, a switched-off account loses its session with the next request, the last active administrator can be neither switched off nor demoted, passwords are asked at a hidden prompt, and every change goes to the `app.audit` log without a password. A *Two-factor* link in the page header lets anybody turn MFA on when it is optional. [deploy.md](deploy.md#team-accounts) has the table of commands and the sharing rules.
- *Left for later:* roles beyond administrator and member, groups or per-person grants, transferring an assessment to another owner, SSO (S5.5).

**S3.4 Deploy kit** (M) — `docker-compose.yml` (web, worker, db), `.env.example`, quickstart, reverse-proxy and backup notes.
- *Built (2026-10-06, ahead of S3.2 at the user's request):* a `Dockerfile` of three stages (Tailwind and htmx built in a Node stage, so no stale stylesheet ships; the locked Python dependencies with gunicorn from the new `deploy` group; a slim runtime that runs as an unprivileged user) and `docker-compose.yml` with `db` (PostgreSQL 17 on an internal network that has no route out and publishes no port), `migrate` (`flask db upgrade`; web and worker start only after it succeeded), `web` (gunicorn, published on `127.0.0.1:8080`), `worker` (stops cleanly on SIGINT in about a second, can be scaled) and, behind profiles, `cli` (one-off commands: create the admin, `datasets update`) and `proxy` (Caddy, HTTPS). The containers are read-only, run without capabilities and with `no-new-privileges`, with memory and process limits and rotated logs; the only writable place is the `datasets` volume. The build context excludes `.env` and `var/` (the `.dockerignore` that was there did not). One change in the application: **`TRUSTED_PROXY_COUNT`** (`ProxyFix`, client address and scheme only, never the host). The sign-in limit counts failures per address and behind a proxy every client had the proxy's address, so five failures from anybody would have blocked everybody for 15 minutes; with the setting at 0 and a forwarding header arriving, the log says so once. [deploy.md](deploy.md) has the quickstart, HTTPS options (the bundled Caddy, an nginx snippet), upgrades, backup and restore, which secrets must never change (another `SECURITY_PASSWORD_SALT` invalidates every password, another `MFA_ENCRYPTION_KEY` every enrolled authenticator: both verified) and what the worker's egress means. Verified with Docker 26 and Compose 2.26 in WSL: the build, the first start, a badssl.com scan in the containers with the location data in the volume, the report and the exports, the proxy over HTTPS with the `Secure` cookie and the strict CSRF referrer check, the clean worker stop, scaling, backup and restore into an empty volume and the error messages for a missing password or secret; `tests/test_deploy_kit.py` keeps the files honest without Docker.
- *Left for later:* publishing the image, a CI job that builds it, TLS for the database connection (it never leaves the internal network), IPv6 inside the containers.

**S3.5 Guardrails** (S) — per-user scan rate limit, host-cap enforcement, audit log (login, scan create/delete, export, finding accept/reopen).
- *Built (2026-10-06):* **The audit log** is a table, `audit_event` (migration 0003), that every service writes through one function, `app.service.audit.record`, *in the transaction of the change it records*, so there is no entry without the change and none missing for it; the same fact goes as one line to the `app.audit` logger for a log collector. It covers sign-ins (signed in, signed out, failed, password changed, two-factor changed), assessments (created, shared, made private), hosts (added, removed), scans (started, cancelled, refused), findings (accepted, false positive, reopened), the four exports and every change to an account (`flask users …`, which writes "command line" as the origin). Entries hold codes, ids, counts and rule ids, never a password, a secret or the reason of a decision (a test greps for one), `details` is cleaned to twenty short, plainly named facts, and the links to the person and the assessment are cleared when those are deleted while the e-mail address and the domain stay as text. A failed sign-in is recorded only for an address that has an account: the address typed for one that has none may be a password in the wrong field, and strangers must not be able to fill the log. Administrators read it on **`/audit/`** (a link next to *Assessments*; 404 for everybody else, link included) with filters for kind, action, person, time and assessment, paged at 50, and with **`flask audit list`**; the worker removes entries older than `AUDIT_RETENTION_DAYS` (730, 0 = for ever) hourly. **The scan limit** is `MAX_SCANS_PER_USER_PER_HOUR` (20, 0 = off): a count of the scans the person started in the last hour, checked after "a scan is already running" so each message is true, answered with the number of minutes until the oldest of them is an hour old and recorded as `scan.refused`; it is a brake, not a meter (two requests in the same instant can both pass). **The host cap** now has a ceiling: `MAX_HOSTS_PER_RUN` may not exceed 2000 (the application will not start with more), a scan stores `min(setting, 2000)` and the planner clamps whatever it reads from the row to 1…2000, so neither a stale option nor a hand-edited row lifts the limit. Two defects surfaced on the way and are fixed: **changing a password ended in an HTTP 500** (after the new hash had been stored) because Flask-Security tried to send a notice by mail and there is no mail server (`SECURITY_SEND_PASSWORD_CHANGE_EMAIL` is off now; S3.3 added the *Password* link without exercising it), and **a housekeeping step that failed failed the whole worker round**: a worker started against a schema that was not migrated yet (no `audit_event` table) logged a failed first round, so cache and audit clean-up are now logged and skipped on their own. Sign-out has no Flask-Security signal (its `user_unauthenticated` fires when an anonymous visitor reaches a protected page), so the entry comes from Flask-Login's `user_logged_out`; changing the password re-creates the session, which is not recorded as a sign-in. Verified live in a throw-away schema with a real scan of badssl.com: a failed sign-in of a known and of an unknown address (one entry), two scans, one cancelled, a third refused with "…the most scans allowed in an hour (2). The next one can start in about 59 minutes.", an acceptance, a false positive and a reopened finding (the reason text appears nowhere in the page), the three exports and the report, sharing and un-sharing, a host added and removed, a password change, 25 entries in the right order on the page and in `flask audit list`, the filters, a page past the end shows the last one, a colleague gets 404 and no link, and the page does not overflow at 375 px (the table scrolls inside its own frame). `tests/test_audit_log.py` and `tests/test_guardrails.py` cover the rest, and `test_models_match_migrations` the table.
- *Left for later:* there is no deleting of scans or assessments yet (wanted: see the backlog; when there is, it must write `scan.deleted` / `assessment.deleted`: the roadmap's "scan create/delete" meant start and cancel); refused requests (403/404) are not logged; no export of the log, no hash chain or other protection against somebody with write access to the database (ship the `app.audit` lines for that), no alerts.

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
| S5.4 | de-CH report; complete UI translation (a server-side PDF is a Pro feature: see the backlog) |
| S5.5 | SSO/OIDC and per-assessment grants (old access design as reference) |
| S5.6 | Simple retention (delete scans older than N days) and backup guidance |
| S5.7 | Scheduled re-scans and alerts (email / webhook) |
| S5.8 | TPRM export / API |

### Backlog — decided in the R3 review (2026-10-06)

**Direction.** The tool is used internally and published as open source. A professional SaaS ("Pro") version may follow later; what only makes sense there stays out of the open-source core until then. **To discuss before any Pro work starts:** the best way to approach that plan: what is core and what is Pro, how it is hosted and sold, and what that means for the licence, for the terms of the data sources (InternetDB and ip-api are non-commercial) and for support.

**Accepted as it is for now:** one team with private or shared assessments plus administrators (separate teams belong to the SaaS stage); the reasons of accepted findings are in the report and the JSON for everybody who can open the assessment; the audit log (no further investment).

| Item | Notes |
|---|---|
| Separate teams (tenants) | Pro / SaaS. Today there is one team; sharing is per assessment. |
| Self-service password reset | Needs a mail server (reset mails and tokens: Flask-Security `recoverable`), so it waits for a deployment that has one. Until then an administrator runs `flask users set-password`. |
| Server-side PDF report | Pro. The printable report and the browser's "Save as PDF" stay in the core. This is the PDF half of S5.4; settle it together with the plan above. |
| Archive and delete assessments and scans | **Wanted**, to declutter the dashboard. Sketch: *archive* hides an assessment from the default list (reversible; owner or administrator); *delete* a scan or an assessment after a confirmation, cascading, refused while a scan runs, and written to the audit log (`scan.deleted`, `assessment.deleted`, the domain kept as text, which the table already supports). Age-based clean-up is S5.6. |
| Audit: say which factor signed somebody in | An authenticator sign-in is recorded as "Signed in" without a detail, because Flask-Security's signal arrives without `authn_via` at the end of the second step (a password sign-in says `via password`). One line could infer it from the person's authenticator. Not pursued: the audit log is accepted as it is. |
| Publish the container image | Not now. |

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
