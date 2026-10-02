# Configuration design

Status: proposed configuration contract; these are not implemented settings.

Read [the coding-agent index](README.md), [collection contracts](design/collection.md) and [evidence lifecycle](design/evidence-reporting.md) alongside this document. Names below are the proposed configuration API for implementation; validate them centrally rather than scattering environment lookups through services.

Keep deployment configuration centralised, validated at startup and separate from per-assessment collection policy. Store secrets in approved secret injection/management; use database records only for secret references and non-secret provider metadata. Record a redacted effective configuration version with every scan.

| Area | Configuration and safe behaviour |
|---|---|
| Identity | Phase 1 local team accounts with MFA, administrator-controlled invitations, secure recovery and no public signup; OIDC settings/integration deferred |
| Persistence | PostgreSQL connection and runtime role; private `filesystem` artifact backend proposed initially, optional `s3` or size-limited `database`; no required hosting country or managed provider; keys and credentials never appear in browser responses |
| CT | Free/Standard capability profile, credential reference, concurrency, quota and usage reconciliation; refuse Free in configured commercial operation |
| Other providers | Enabled adapters, entitlement checks, timeouts, allowed retention/report use and credential references; missing access yields explicit incomplete coverage |
| Collection | Scope rules, host/IP budgets, timeouts, response/screenshot limits and per-domain concurrency; administrators cannot permit internal network access through an assessment form |
| Browser | Runner endpoint/identity, enforced egress policy, viewport, browser version and resource ceilings; no arbitrary command or user-supplied browser flags |
| Evidence | `RETENTION_MONTHS=12` default, configurable per record class; explicit clock/expiry, authorised holds, daily purge, redaction, hash/manifest policy and optional archive signing |
| Sharing/reporting | Default private, permitted role transitions, grant expiry, download permissions, required `en`/`de-CH` report languages, optional four-eyes policy and manual TPRM reference |
| Localisation | Independent UI/report locale, language-neutral statuses and versioned message catalogs; full DE/EN UI translations desirable; original source evidence preserved |
| Operations | IT Security ownership, queue leases/retries, monitoring and scheduled backups with bounded expiry; no strict availability/recovery SLA; audit retention separately configurable, default 12 months |

Production startup must fail if core identity, DB or storage security configuration is missing. An optional provider outage must leave the application usable while showing the affected checks as unavailable. Do not conflate `disabled`, `not_licensed`, `quota_exhausted`, `error` and `no_match`.

Implement adapters as ordinary reviewed Python modules with explicit registration. A new adapter needs a typed schema, fixed upstream endpoint policy, scope and quota behaviour, credential redaction, retention/export rules, fixture tests and evidence documentation. No runtime installation of arbitrary plugins.

Report templates consume a frozen application-defined snapshot. Customise branding, wording and language without embedding executable user templates or loading external resources. Changes to interpretation rules/template versions apply to new reports and are recorded for reproducibility.

DE/EN report variants use identical technical facts and IDs with separate rendered hashes; adding a translation does not reset report expiry. Use Swiss Standard German for DE. Original provider text and analyst notes are not silently translated or sent to external translation services. There is no configurable questionnaire or vendor-document collection module.

Final reports are manually transferred to the leading TPRM tool in Phase 1. An optional recorded handoff reference is metadata, not an API integration or proof from a download event. TPRM retention is independent of local expiry. IT Security handles maintenance and recovery during working hours; manual due diligence is an acceptable fallback.

The user has set team-only Phase 1 access, deferred SSO and configurable 12-month retention, and rejected a requirement for Swiss-hosted managed object storage. The private filesystem backend and precise retention clocks are proposed implementation choices, documented in [architecture.md](architecture.md). Do not require OIDC configuration for Phase 1 startup.

Retention configuration affects new records by default. Persist the applied policy version and expiry date; bulk retroactive changes need a reviewed impact preview. Existing report packages keep their evidence until their own expiry, subject to holds and provider rights. Configure backup expiry independently and document any residual retention after live-data deletion. Restoration must reapply deletion records before serving users.

Possible Phase 2 open sourcing requires configuration examples with placeholders and synthetic fixtures only; never include deployment secrets, team identities or collected/licensed evidence. The chosen source-code licence does not replace provider contracts.

## Typed settings and ownership

| Setting | Type / baseline | Validation and owner |
|---|---|---|
| `APP_ENV` | `development/test/production` | Deployment-owned; no implicit production debug |
| `DATABASE_URL` | Secret connection reference | Required; separate migration and runtime roles |
| `SECRET_KEY`, `MFA_ENCRYPTION_KEY` | Separate injected secrets | No defaults; production startup rejects missing values; never include in config snapshots |
| `AUTH_MODE` | `local` | Only Phase 1 supported mode; OIDC is not a half-enabled placeholder |
| `SESSION_IDLE_MINUTES` | Positive integer; proposed 30 | Validate upper bound; recent MFA for privileged actions has its own shorter window |
| `STORAGE_BACKEND` | `filesystem` initially | Optional backends are accepted only when implemented and validated |
| `ARTIFACT_ROOT` | Absolute private path | Required for filesystem; must not be web/static root; no client-controlled path |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION` | Backend-specific values | Only required when S3 is implemented/enabled; credentials injected separately |
| `COMMERCIAL_USE` | Boolean, default true | Internal business operation is commercial; Free evaluation requires deliberate non-commercial configuration |
| `CT_ENABLED`, `CT_PLAN`, `CT_API_KEY_REF` | Enabled flag, `free/standard`, secret reference | Enforce plan compatibility; provider balance/limits override optimistic local settings |
| `SHODAN_ENABLED`, `SHODAN_API_KEY_REF` | Enabled flag, secret reference | Entitlement check must distinguish missing capability from no result |
| `REPUTATION_PROVIDER`, `REPUTATION_KEY_REF` | Explicit adapter or `disabled` | No live provider default before rights/entitlement configuration |
| `PROVIDER_RIGHTS_POLICY_VERSION` | Versioned configuration ID | Defines retention/export capabilities; fail closed for unspecified uses |
| `RUNNER_ENDPOINT`, `RUNNER_IDENTITY_REF` | Operator-owned endpoint/transport identity | Fixed authenticated control channel; never user-configurable target callback |
| `MAX_HOSTS_PER_RUN`, `MAX_IPS_PER_HOST` | 1,000 / 16 | Positive bounded values; reaching cap records partial coverage |
| `NETWORK_CONCURRENCY_PER_DOMAIN`, `SCREENSHOT_CONCURRENCY` | 4 / 2 | Enforced across workers/runner, not merely per process |
| `CONNECT_TIMEOUT_SECONDS`, `REQUEST_TIMEOUT_SECONDS`, `SCREENSHOT_TIMEOUT_SECONDS` | 5 / 15 / 30 | Connect <= request; explicit wall deadlines |
| `MAX_RUN_HOURS`, `JOB_LEASE_SECONDS`, `JOB_HEARTBEAT_SECONDS` | 24 / 120 / 20 | Heartbeat materially below lease; reject incoherent values |
| `RETENTION_MONTHS`, `AUDIT_RETENTION_MONTHS` | 12 / 12 | Positive calendar months; per-class overrides explicit and versioned |
| `STAGING_TTL_HOURS` | 24 | Longer than bounded active stage lease; purge does not race active work |
| `BACKUP_RETENTION_DAYS` | No production default | Operator must set finite positive period before production backup enablement |
| `FOUR_EYES_REQUIRED` | false, pending policy decision | Every issue operation snapshots/rechecks current policy |
| `REPORT_LOCALES`, `DEFAULT_UI_LOCALE` | `en,de-CH` / `en` | Reports must support both; unsupported locales rejected, not interpolated as paths |

Provider keys should be references to injected secrets, not database strings returned to the UI. Production startup validates core application security/storage/identity settings; optional provider configuration errors disable the affected check with an actionable status rather than make existing reports inaccessible. A missing required core secret is fatal. A runner failing public-only egress readiness is not allowed to collect targets.

Precedence: safe code defaults, deployment settings, then versioned workspace policy where explicitly permitted. Assessment inputs may narrow scope/budgets, not relax network/security controls or source rights. Store an allowlisted redacted effective snapshot for each run/report. Do not dump the full environment to logs, reports or diagnostic endpoints.

Use explicit typed parsing: the text `false` must not become true merely because it is nonempty. Validate cross-field constraints at startup/policy change. Policy mutations require administrator authority, recent MFA and audit, with separate review for retroactive bulk retention changes. Changes to provider credentials use a deliberate replacement/rotation process, not hardcoded fallbacks.

## Extending checks safely

Add a fixed registered adapter, typed schema, pure normaliser and explicit technical rule/message catalog entries. Document the source licence, cache/archival distinction, credential submission, requests/credits, subject attribution, freshness, failure modes and fixture tests. New target protocols/ports or authenticated access change the approved collection scope and cannot be enabled merely by adding a plugin setting.

Add new storage drivers only behind the defined artifact interface with traversal/isolation, hash, retry, version deletion and restore tests. Add new report locales through catalog review and visual QA against the frozen snapshot. New catalog/template versions must not overwrite issued artifacts.
