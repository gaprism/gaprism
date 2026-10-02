# Coding-agent documentation index

Design baseline 1, 2026-10-01. Documentation only: no application, migrations, dependency lockfiles or runtime tests have been implemented. The following contracts guide future authorised implementation; they do not authorise deployment, publication or live collection by themselves.

## Reading order

1. Read every file in `../rules/` and the current user instructions.
2. Read [architecture.md](architecture.md) for product scope, rationale and trust boundaries.
3. Read [design/application.md](design/application.md) for modules, use cases and HTTP contracts.
4. Read [design/data-model.md](design/data-model.md) for persistence, states and invariants.
5. Read [design/access-control.md](design/access-control.md) before implementing any data access.
6. Read [design/collection.md](design/collection.md) before jobs, integrations or target requests.
7. Read [design/evidence-reporting.md](design/evidence-reporting.md) before artifact storage, reporting or deletion.
8. Use [contribute.md](contribute.md), [customizing.md](customizing.md) and [design/implementation-plan.md](design/implementation-plan.md) while implementing and validating changes.

The design documents define precise Phase 1 contracts; the overview explains why. If they conflict, resolve the inconsistency against the user's decisions before changing security-sensitive behaviour. Do not infer that an open operational choice overrides a specified control.

## Confirmed scope

| Decision | Contract |
|---|---|
| Product | Pure technical verification of public SaaS infrastructure; no questionnaire, vendor-document workflow or supplier risk acceptance |
| Users | Internal team, private assessments and explicit sharing; local authenticated accounts now, SSO later |
| Collection | CT discovery, public DNS/TLS/HTTP and screenshots; Shodan observations for ports/CVEs; reputation checks; no exploitation or active port scan |
| Framework | Flask factory/Blueprints, Jinja/HTMX/Tailwind, PostgreSQL, small background workers |
| Reports | DE (`de-CH`) and EN, fixed evidence snapshots; authoritative final copies in TPRM via manual handoff |
| Languages | Application-owned text is translation-ready; complete translated UI is an enhancement |
| Retention | Configurable, default 12 calendar months; TPRM retention independent |
| Operations | IT Security; non-critical, normal working-hours recovery, manual assessment fallback |
| Phase 2 | Possible open-source code release; no implied public hosted service |

## Design choices agents may implement as the baseline

These are engineering defaults, not new business requirements: private filesystem artifact backend; optional storage interface for S3; PostgreSQL durable jobs; one assessment scope per scan; one terminal scan per report version; optional four-eyes review; report-only access to one version; structured technical rules with no opaque supplier score. See the owning documents for details.

Alternatives deliberately deferred: Web Check as a separate backend (extra runtime/normalisation boundary), a broker (extra infrastructure), database blobs for ordinary screenshots (backup growth), enterprise identity integration, active scanners and custom runtime plugins. Reconsider only with evidence that the baseline is insufficient.

## Open decisions and their effect

| ID | Open item | Working default / implementation impact |
|---|---|---|
| OPEN-01 | Domain sizes and volume | Configurable caps from [collection](design/collection.md); implement bounded execution, then measure; no claimed capacity guarantee |
| OPEN-02 | Mandatory four-eyes review | Configurable, off by default; retain approval model and enforce it when enabled |
| OPEN-03 | Actual hosting/backend | Private filesystem on trusted app/coordinator host plus isolated target runner; retain S3 interface, do not provision a provider |
| OPEN-04 | Backup expiry and precise retention clocks | Proposed clocks in [evidence](design/evidence-reporting.md); production operator must explicitly configure backup expiry; no silent unlimited backups |
| OPEN-05 | Provider budgets and retention/export rights | Implement adapters with fixtures and disabled/unlicensed states; enable real calls and report inclusion only under configured entitlements |
| OPEN-06 | Open-source licence | Defer to Phase 2; preserve third-party notices now; do not publish code or data |

Unresolved provider contracts do not prevent offline development of adapters, parsers, reports and tests. They do prevent claiming licensed production completeness. Unresolved hosting does not justify running hostile pages beside application credentials.

## Cross-cutting invariants

- INV-01: A role never grants access to an unrelated assessment.
- INV-02: Report-only access never grants underlying case, job, host or raw-artifact access.
- INV-03: Every collected fact identifies its subject, source, time and collection method.
- INV-04: No data, no match, not licensed and collection failure are different outcomes.
- INV-05: A CT entry is not live certificate validation; an IP observation is not automatic hostname attribution.
- INV-06: All target traffic crosses enforced public-only egress; target execution holds no application credentials.
- INV-07: Issued report content and artifact bytes never change; corrections create a new version.
- INV-08: Retrying jobs cannot create duplicate logical observations or accept stale worker results.
- INV-09: Access expires at the policy deadline even if physical deletion is delayed.
- INV-10: DE and EN reports describe identical facts; raw evidence is preserved in its source language.
- INV-11: Export/download is not proof of confirmed TPRM transfer.
- INV-12: No network work, scheduler or migration starts as an import-time side effect.

Implementation PRs should identify relevant invariants and their verification. See the acceptance matrix rather than generating superficial tests for every file.
