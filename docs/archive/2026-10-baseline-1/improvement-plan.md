# Code review and improvement plan

> 2026-10-04 · Basis: static review of `app/` and `runner/`, a run of the tests that do not need DB-admin rights, probes against the configured WSL Postgres, and the new roadmap (no longer in the repository). Findings are **verified** unless marked *(inference)*.

## 1. Verdict: selective rebuild

Keep the small, security-critical, well-tested core; rebuild the schema, execution, views and UI around it as thin vertical slices. A pure refactor would spend most of its effort peeling off tenancy, RLS, grants and a lease-fencing queue that a 1–5 person tool does not need; a greenfield rewrite would re-pay for SSRF, TLS and scope handling that already work.

| Measure | Value |
|---|---|
| Code | `app/` 4,910 · `runner/` 748 · `tests/` 4,389 · `migrations/` 2,210 lines |
| Data model | 22 tables; 16 carry `workspace_id` |
| Tests | 167 collected. 99 run without DB-admin rights: **95 pass, 2 fail, 2 error** (the errors need the DB). 68 were not run (DB harness refuses this role / needs Playwright browsers) |
| Reusable | ≈ 2,000 of ≈ 5,700 non-test lines (~35 %) kept, ported or adapted, plus their tests |
| Docs | ≈ 514 KB of planning docs; the documented reading order alone is ≈ 158 KB (~40 K tokens) per agent session |

## 2. Findings

| # | Sev. | Finding | Evidence | Fix |
|---|---|---|---|---|
| F1 | **Blocker** | The live UI cannot render. `base.html` is the design-preview shell (`_()`, `page_url()`, `locale_url()`, `g.locale`, a `preview` blueprint) and nothing provides them | Rendering `base.html` in a fresh app raises `UndefinedError: '_' is undefined`; registered blueprints are only `security`, `assessments` | S0.4 |
| F2 | **Blocker** | Tests cannot run on the configured Postgres | `tests/conftest.py:39` demands a fresh DB `due_diligence_test_<32 hex>`; the role has no CREATEDB; in the dev DB `public` is owned by `postgres` (no CREATE) | S0.2, S0.3 |
| F3 | High | Over-scoped data model: 22 tables, 16 with `workspace_id`, RLS helper functions (`migrations/versions/0005_*`, 24 KB) that need privileged roles, three overlapping run models (`scan_run`, `run_host`, `job`) | `app/models/*`, migrations | S0.2 |
| F4 | High | Scope validation accepts public suffixes: `co.kr`, `com.mx`, `co.in`, `ne.kr`, `blogspot.com`, `myshopify.com`, `azureedge.net` are accepted as assessment scope | `psl.py` is a hand-curated list (~180 entries, "2026.1-curated"); a scan of such a "domain" enumerates unrelated third parties | S1.1 |
| F5 | High | CT discovery supports a single source. The ctlogs.dev adapter is correct against the live API (`?after=` cursor, `hosts` / `has_next` / `next_cursor` envelope — verified 2026-10-04) but is padded with three guessed schemas (`ct.py:138-210`) and ignores the live-DNS fields; CertSpotter and crt.sh are missing; persistence is bound to the old model. crt.sh failed 4 of 4 probes | `ct.py`, probes on 2026-10-04 | S1.2 |
| F6 | Medium | `host_inventory` loads every host, check result and finding of an assessment into Python and filters/sorts in memory; the view is 536 lines of business logic | `views.py:322-507` | S1.9 |
| F7 | Medium | GeoIP was deliberately switched from a MaxMind DB to ipwho.is; the 2 failing tests encode the old contract, and the default `allow_fallback=True` makes unit tests call the live API | `geoip.py:59`, `tests/checks/test_adapters.py:18-31` | S0.3, S2.1 |
| F8 | Medium | CSP allows `'unsafe-inline'` scripts, which removes most of CSP's XSS protection | `app/__init__.py:81-86` | S0.4 |
| F9 | Medium | Valuable work is untracked: auth rate limit, RLS migrations 0005/0006, `tests/security/*`, `tests/session_helpers.py` | `git status` | S0.1 |
| F10 | Low | The egress client collapses duplicate headers, so multiple `Set-Cookie` values are lost | `runner/egress.py:142` | S1.8 |
| F11 | Low | `EGRESS_DNS_RESOLVERS` and the egress timeouts are configured but nothing reads them; DNS uses the system resolver | `config.py:75-77` | S1.6 |
| F12 | Low | Playwright is a core dependency but only used by one test and the parked browser runner; `bcrypt` and `argon2-cffi` are both declared (config selects argon2); `dnspython` arrives only transitively | `pyproject.toml` | S0.5 |
| F13 | Low | Repo hygiene: `.idea/`, `.junie/`, `.aiassistant/` are tracked; `.gitignore` is copied from another project (huggingface, pg_data…); the root-level `templates/` folder is an unused older copy of `app/templates` (8 files, none identical; the factory only reads `app/templates`; `assets/` is the Tailwind source and is fine); `docs/ui/` mirrors `docs/` (6 of 10 shared files byte-identical); `base_.html` is a leftover; docs still say "documentation only, no application implemented" | repo | S0.1 |
| F15 | Medium | The Shodan adapter may drop CVEs: it reads the top-level `vulns` as a dict, but Shodan's host response lists CVE IDs there and keeps details in each banner's `vulns` *(from Shodan's documented shape; not yet checked against a real response)*. Its tests use hand-written fixtures with the same assumption. The API key is sent as a query parameter, so URLs in logs or exceptions would leak it | `shodan.py:162,268-299`, `tests/checks/test_adapters.py:121-200` | S2.2 |
| F14 | Good | The SSRF gate, TLS prober and scope normaliser are well structured and tested (95 offline tests pass). The egress client verifies the connected peer equals the screened IP and caps redirects, bytes, time and ports; it never sends credentials | `runner/*`, `tests/runner`, `tests/security` | keep |

**Why it got expensive** *(inference, not measured)*: ≈ 514 KB of docs with a mandatory ≈ 158 KB reading order per session; eight horizontal milestones, so the first user-visible result sat at M5; a heavy per-story definition of done (strict typing everywhere, traceability matrix, 12 invariants); premium model tiers assigned to many stories. **Remedy:** the lean process in roadmap §2/§5, a ≤ 60-line `CLAUDE.md`, small vertical stories.

## 3. Module disposition

| Path | Lines | Decision | Notes |
|---|---:|---|---|
| `runner/dns.py` | 157 | **Keep** | Add a stdlib `is_global` cross-check and a dnspython resolver |
| `runner/egress.py` | 133 | **Keep + extend** | Expose raw multi-value headers; read timeouts from config |
| `runner/tls.py` | 302 | **Port** | Becomes check `tls`; keep the forensic read but label it |
| `runner/browser.py` | 133 | Park (R4) | Needs a sandbox decision; move behind an extra |
| `app/service/discovery/scope.py` | 148 | **Keep** | Swap in the real PSL; drop the duplicated check |
| `app/service/discovery/psl.py` | 225 | Replace | `publicsuffixlist` |
| `app/service/discovery/ct.py` | 324 | **Port + extend** | Keep the ctlogs.dev adapter and its strict parser; drop the guessed schemas and the old-model persistence; add CertSpotter and crt.sh behind `DiscoverySource` (union mode) |
| `app/service/checks/tls.py`, `rules.py` | 326 | Adapt | **Done (S2.4):** the check is `app/checks/tls.py` (a typed outcome); the judgement is in `app/rules/`, one package instead of beside each check, so that rules can be re-run over old scans |
| `app/service/checks/geoip.py` | 185 | Rewrite | `GeoIPProvider`: DB-IP City + ASN Lite offline (city, region, country), typed statuses; the ipwho.is call stays as the optional API fallback |
| `app/service/checks/shodan.py` | 276 | **Keep + port** | Primary provider when `SHODAN_API_KEY` is set; re-verify the CVE parsing, redact the key from URLs and logs; add InternetDB as the keyless fallback |
| `app/service/checks/webrisk.py` | 144 | Park (R4) | Removed in S2.4 with the rest of `app/service/checks/`; it is in git history (commit `6c319ee`) and returns as a check plus a rule |
| `app/service/jobs/*`, `models/job.py`, `models/quota.py` | 659 | Replace | Task rows in `check_result` + worker; no leases, fencing or quota ledger |
| `app/service/assessment/run_manager.py`, `models/scan_run.py` | 229 | Replace | Simple scan lifecycle |
| `app/service/access/*`, `models/grant.py` | 357 | Archive | Returns with S5.5 if needed |
| `app/models/assessment.py` (Report, ReportVersion), `annotation.py`, `discovery.py`, `check.py` | 448 | Replace | New 7-table schema (adds `finding_disposition`, `provider_cache`) |
| `app/models/auth.py` | 147 | Trim | Drop `Workspace`, `Membership` |
| `app/service/auth/rate_limit.py` + model | 195 | **Keep** | Fold into the new baseline migration |
| `app/config.py`, `app/commands.py`, `app/__init__.py` | 366 | Simplify | Keep the factory pattern and fail-fast validation |
| `app/blueprints/assessments/views.py` | 536 | Rewrite | Thin views over services; SQL pagination |
| `app/templates/*`, `app/static/*` | – | Rewrite | Keep the Tailwind tokens and HTMX; drop the preview pages and duplicates |
| `migrations/0001–0006` | 2,210 | Archive | One new baseline (empty DBs, no production data) |
| `tests/` | 4,389 | Split | **Keep:** `runner/` SSRF, `discovery/test_scope`, `test_factory`, `security/` egress+config. **Rewrite:** checks, UI. **Drop with their code:** access, rls, jobs, performance, annotation, migrations of old schema |

## 4. Execution plan (after your approval)

0. **Snapshot** *(needs your OK to commit)* — commit the working tree on `flask_app` (including the untracked work) as `chore: snapshot baseline-1`, tag `baseline-1`, continue on branch `mvp`.
1. **S0.1** — archive superseded docs with `git mv`; add `CLAUDE.md`; stop tracking IDE/agent folders. *Verify:* `git status` clean, docs index ≤ 40 lines.
2. **S0.2** — create schema `due_diligence` in the dev DB (the role owns the database, so it may), `DB_SCHEMA` via `search_path`, new baseline migration. *Verify:* `upgrade` → `downgrade base` → `upgrade` on the dev DB with the app role.
3. **S0.3** — per-session test schema, `live` marker, rewrite the GeoIP tests, CI workflow. *Verify:* `uv run pytest`, `ruff check`, `mypy` green locally.
4. **S0.4** — app shell and CSP. *Verify:* log in, see the empty assessments page in the browser pane.
5. **S0.5** — dependency diet and lock refresh. *Verify:* clean install from the lockfile; `pip-audit`.
6. **R1** in this order: S1.1 → S1.2 → S1.3 → S1.9 (list only) → **Demo 1** → S1.4 → S1.5 → S1.6 / S1.7 / S1.8 → **Demo 2**. Each demo is shown in the in-app browser with real data (a harmless domain such as `example.com`).

Each step is its own commit on `mvp`; nothing is pushed without your say-so.

## 5. Test strategy

| Layer | How |
|---|---|
| Unit | Pure functions and checks with fixtures and fake resolver/egress; no network |
| DB | Per-session schema in `due_diligence_test`; transaction rollback per test |
| Engine | Worker end-to-end with fake checks: 100-host synthetic scan; kill-and-restart test |
| Security regression | Keep and extend: private IPs, redirects to private IPs, DNS rebinding, mixed answers, oversized bodies, scope boundaries |
| Live (`-m live`) | Manual/nightly smoke against `example.com` and the public APIs; never in the default run |
| UI | One Playwright smoke test (login → create → see hosts) at each demo |

## 6. Risks and open points

- **Data confidentiality of targets.** Every external lookup tells a third party which vendor you are assessing (CT, InternetDB, RDAP, HIBP). Fine for most due diligence; for M&A work you may want an *offline-only* mode (local datasets, no third-party lookups). The checks are written so each external source can be switched off.
- **Provider terms.** InternetDB, ip-api and a free ctlogs.dev key are non-commercial; they are config-switchable and the terms are in the [catalogue](../../checks-catalog.md#3-free-sources--verified-2026-10-04). A paid ctlogs.dev plan and your Shodan key cover commercial/internal corporate use.
- **Provider keys.** `SHODAN_API_KEY`, `CTLOGS_API_KEY` and `CERTSPOTTER_TOKEN` live only in `.env` (git-ignored). To record real-response fixtures in S2.2 I will read the Shodan key from there without printing it — and ask you before the first use.
- **Licence choice** (S5.1) decides whether AGPL/GPL tools or data may ever be bundled.
- **Auth.** Flask-Security-Too and its MFA flow were not exercised end-to-end here (DB harness); S0.4 includes a manual login test.
- **Estimates** in the roadmap are guesses until R0/R1 give real throughput.
