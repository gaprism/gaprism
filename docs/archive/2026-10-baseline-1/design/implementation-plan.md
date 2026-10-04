# Implementation sequence and acceptance evidence

Owner: delivery boundaries and validation. This is a plan for future authorised implementation, not a claim that the system exists or tests have passed. Read [the index](../README.md) for requirements/open choices and [contributor guidance](../contribute.md) before changing files.

## 1. Incremental delivery

| Milestone | Deliverable | Completion evidence / dependencies |
|---|---|---|
| M0 — foundation | Factory/Blueprint skeleton, config validation, locked dependency setup, local assets, migration pipeline and PostgreSQL test fixture | Two app instances have independent config; startup has no side effects; tests cannot contact public targets; no runtime dependency installed without purpose/version review |
| M1 — private workspace | Local team accounts/MFA, owner and grants, scoped queries/RLS, audit and basic case UI | Two-case access matrix including admin-without-grant; pooled context isolation; CSRF and invitation/recovery tests |
| M2 — durable execution | Run/job state machine, idempotency, quota ledger, cancellation and progress UI | Crash/reclaim, stale-generation rejection, duplicate requests, quota pause and run finalisation races using fixtures |
| M3 — discovery and network gate | CT adapter/fixtures, scope normaliser, DNS/TLS result schemas and isolated runner contract | Wildcard/pagination/IDNA/scope tests; rebinding/redirect/private-IP denial proven at network boundary before public target collection |
| M4 — required enrichment | Location, HTTP metadata, screenshots, Shodan ports/CVEs, reputation; explicit entitlement/error states | Six required result categories represented; stale/shared-IP attribution and failed TLS coverage; licensed providers enabled only after OPEN-05 resolution |
| M5 — technical workspace | Searchable host table/detail, location/provider/security summaries and optional annotations | Bounded queries/pagination; keyboard navigation; safe escaped source text; no questionnaire workflow |
| M6 — evidence and reports | Private artifact driver, fixed snapshot pipeline, DE/EN PDFs, exact-version sharing and manual handoff | Equivalent report facts across locales; visual layout review; hashes, report-only isolation and expiry; failed render cannot publish |
| M7 — lifecycle/operation | Configurable retention, bounded cleanup, backups/restore, runbook and deployment hardening | Expired access denied independently of cleanup; source expiry preserves retained report; restore deletion replay; IT Security ownership and configured backup lifetime |

M1 access scaffolding and M2 job state are required before persisting real supplier evidence. M3's egress gate is required before browsing public targets, even in a demo. M6 cannot be considered complete with placeholder language variants or unlicensed report inclusions. Do not merge a feature solely because its happy-path UI works.

## 2. Test strategy

Use pytest for focused Python unit/integration tests, a real disposable PostgreSQL instance for migrations/RLS/locks and Playwright for a few critical UI flows plus rendered report inspection. Exact test tooling/version choices belong in initial dependency setup. SQLite is not a substitute for PostgreSQL policy, constraint or queue tests.

Default tests use synthetic provider responses and controlled local web/DNS fixtures; public internet collection is opt-in and excluded from normal CI. The test runner's private fixture network is isolated from production configuration; no production bypass flag is introduced. Mock only I/O boundaries, not every internal function. Use explicit clocks, deterministic IDs and controlled fault injection for lifecycle tests.

| Test ID | Behaviour | Evidence to retain |
|---|---|---|
| ACC-01 | Owner/analyst/reviewer/viewer/report-only/admin matrix across two cases and versions | Passing route/service/RLS tests, including thumbnail/search/export variants |
| ACC-02 | Missing context, pooled connection reuse, foreign scope references and self-grant attempts fail | DB integration results with non-owner runtime roles |
| COL-01 | CT duplicate pages/cursors, empty lookup, wildcard-only names, IDN and boundary names | Parser/scheduler fixture tests and explicit partial coverage assertions |
| COL-02 | Expired/untrusted/mismatched TLS and mixed endpoint success remain visible | Result/verdict/skip assertions, no `verify=False` fallback |
| NET-01 | Private IPv4/IPv6, metadata, redirects, mixed answers and rebinding denied | Collector tests plus network-level observation that forbidden destinations received no connection |
| NET-02 | Browser subresources, service workers, WebSockets/QUIC/WebRTC cannot bypass egress | Isolated adversarial target tests and runner configuration review |
| JOB-01 | Worker dies before call, after call and before commit | At-most-one accepted logical result, documented possible repeat billing |
| JOB-02 | Stale lease worker cannot persist after reclaim/cancellation | Concurrency test with independent DB connections |
| JOB-03 | No early terminal run while another completion creates children | Producer-close/finaliser race test |
| PRV-01 | Provider 404, 401/403, 429, timeout, malformed/oversized payload differentiated | No false `no_match` or complete coverage |
| FIND-01 | CDN/shared IP CVE, old banner and provider verification preserved without false hostname certainty | Rule fixtures and grouping/count assertions |
| EVD-01 | Staging failures, orphan files, corrupt/missing artifacts and filesystem traversal rejected | Storage integration tests, no silent artifact omission |
| REP-01 | Editing/re-running does not alter issued report; approval invalidated by content change | Snapshot/hash and concurrent-publication tests |
| REP-02 | Report recipient cannot access source artifacts or other versions | Route and RLS tests after source expiry and grant revocation |
| LNG-01 | DE/EN facts/IDs/severity identical, `de-CH` prose, long text/fonts/pages valid | Structural snapshot comparisons plus visual review of representative PDFs |
| RET-01 | Calendar-month expiry, hold, draft expiry, retries and record-class overrides | Clock-controlled tests, including leap-day and expired-but-not-purged reads |
| OPS-01 | Restore records/artifacts consistently and replay deletion before serving | Recorded restore drill in controlled environment |
| UX-01 | Start scan, filter host table, inspect evidence and export report using keyboard | Focused browser flow/accessibility review |
| PERF-01 | Proposed 1,000-host fixture stays bounded in memory/query count and responsive pagination | Recorded measurement, host spec and unresolved bottlenecks; no invented SLA |

Do not require arbitrary code-coverage percentages or a separate test for each DTO field. Require meaningful negative tests for identity, network, persistence and evidence boundaries. Add regressions for defects discovered in those boundaries.

## 3. Continuous integration and versioning

Initial CI should run formatting/lint/type checks, unit tests, PostgreSQL migrations/integration tests and dependency/secret scanning. Run browser/report tests where the runner can provide required sandboxing; do not disable Chromium security just to make CI green. Container image and dependency scans use current results; record accepted exceptions and owners rather than claim vulnerability-free software.

Use a Python `pyproject.toml` with constrained direct dependencies and a chosen reproducible lock workflow. Lock frontend build dependencies too; build Tailwind/HTMX assets locally. Pin production images by digest, and keep browser package/image versions compatible. Select maintained versions at implementation time, document the compatibility decision, and avoid copying latest version strings from this design as if they were tested.

Schema, provider adapter, rule, collection profile, snapshot, template and translation catalog each have an explicit version. Not every code change increments all of them; changes that affect persisted interpretation/rendering increment the relevant version and add backward-read tests. Issued snapshots remain readable under schema evolution.

## 4. Operational design

IT Security is accountable for account onboarding/offboarding, credentials and entitlements, updating dependencies/browser images, observing failed jobs and quota, report handoff, retention/backup configuration and recovery. Phase 1 has normal working-hours support, no availability SLA and manual technical due diligence as fallback. Keep confidentiality/integrity controls even though downtime is tolerable.

Runtime roles: TLS reverse proxy, web process, trusted coordinator, PostgreSQL, private evidence store, restricted runner supervisor/target sandboxes and offline renderer. A scheduler/CLI process can periodically enqueue cleanup/reconciliation with a DB uniqueness key; no scheduler thread per web worker. Docker Compose supports local trusted services; production target isolation must be provisioned separately or equivalently enforced.

Health checks distinguish process liveness, DB/storage readiness and individual provider availability. A provider outage leaves the UI and existing reports accessible. Readiness responses expose no secrets or supplier identifiers. Metrics: queue age, failed checks, quota balance/staleness, job lease loss, denied destinations, renderer failures, overdue deletion and artifact integrity failures. No high-cardinality domain labels in public monitoring.

Before the first deployment, supply an operator runbook under `docs/` with: bootstrap and MFA recovery, config/secret rotation, safe start/stop, worker reclaim, provider quota/entitlement failure, staging reconciliation, missed cleanup, report handoff, backup/restore and rollback. Commands must be tested against the implemented project; do not invent runnable commands now.

## 5. Migration, release and rollback gates

Review generated migrations, RLS and grants. Deploy compatible schema additions before application changes; postpone destructive cleanup until old code/data paths are retired and explicitly authorised. Never run migrations from web startup. Capture a tested recovery point before risky schema/data changes.

A release candidate needs: applicable acceptance tests, representative DE/EN reports inspected visually, no unresolved critical access/egress issue, provider entitlement/rights configuration, bounded retention/backup expiry and a deployment/restore procedure. Performance and noncritical availability limitations can be documented; report-only leakage or internal-network access cannot be accepted as a demo shortcut.

Rollback means use a compatible prior application and immutable report artifacts. It does not mean force a destructive schema downgrade or regenerate old reports from current scans. If data is lost, restore/reconcile or rerun working assessments; final TPRM reports remain authoritative.

## 6. Work record for coding agents

Before a meaningful change, identify affected contracts, current implementation and relevant invariant IDs. Compare the smallest local extension with any broader alternative only when a real design choice is required. Implement the focused change, update the owning document and run relevant checks. Do not modify unrelated rules, broaden target scope, publish source code or configure production access as a side effect.

The completion note records: behaviour changed, files touched, tests actually run, remaining failures/unknowns and any new operational requirement. State explicitly if validation was fixture-only or no live provider account was available. Never say that this documentation proves implementation security or provider licensing.
