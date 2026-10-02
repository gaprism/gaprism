# Technical Due Diligence Platform — Project Backlog & Decisions

Status: Active Baseline  
Target: Phase 1 Monolith Delivery  
Date: 2026-10-01  

---

## 1. Open Architectural Decisions & Tracking

To maximize reliability and reduce project risks, open decisions are explicitly tracked with concrete defaults and clear impact analyses.

| ID | Title | Context & Trade-offs | Working Default (Phase 1) | Impact on Delivery & Scope | Status |
|---|---|---|---|---|---|
| **OPEN-01** | Domain Size Caps & Host Scan Volume | High host volume increases memory footprint and worker execution time. Uncapped discovery risks resource exhaustion. | Configurable cap: default `MAX_HOSTS_PER_RUN = 1000`, `MAX_DISCOVERY_PAGES = 50`. | Discovery paging halts when cap is hit; records partial coverage warning. Bounded queries protect system stability. | Tracking |
| **OPEN-02** | Mandatory Four-Eyes Review Governance | Strict two-person sign-off enhances security assurance but introduces workflow friction for single-analyst teams. | Configurable per instance: `FOUR_EYES_ENABLED = False` by default. Workflow and status checks support both modes. | Single analyst can issue reports by default; when enabled, reviewer cannot be the assessment author. | Tracking |
| **OPEN-03** | Artifact Storage Backend & Runner Hosting | Production S3/MinIO requires external service dependencies, whereas local filesystem is self-contained and immediately verifiable. | Abstract `StorageDriver` interface implemented with private filesystem volume (`/var/data/evidence/`). | Local filesystem with atomic staging and SHA-256 validation; S3 driver interface ready for Phase 2 plug-in. | Tracking |
| **OPEN-04** | Backup Expiry & Retention Clocks | Retaining database backups longer than data retention policy (12 months) creates regulatory compliance exposure. | Default 12 calendar months with leap-day clamping (`Feb 29 -> Feb 28`). Backup lifetime strictly bounded to 365 days. | Daily deletion journal records purged record IDs to replay purges onto restored backup snapshots. | Tracking |
| **OPEN-05** | External Provider Licensing & Budgets | Shodan and Google Web Risk require commercial API credits and specific data export terms. | Synthetic fixtures for CI/tests; adapters support `unlicensed` / `quota_exhausted` states without UI failure. | Live API calls require configured API keys; unconfigured providers yield clean diagnostic notices rather than crashes. | Tracking |
| **OPEN-06** | Open-Source Distribution & Licensing | Releasing the codebase publicly requires sanitized commit history, third-party attribution, and clean license audit. | Defer public release to Phase 2. Preserve third-party notices and keep internal repository private. | No public package publication or external dependencies with copyleft conflicts. | Deferred |

---

## 2. Deferred Scope (Phase 2 & Beyond)

To maintain focus on the core value proposition of technical SaaS due diligence without unnecessary complexity, the following capabilities are deferred:

1. **Enterprise Identity (SSO / OIDC / SAML)**:
   - *Rationale*: Local database authentication with enforced TOTP MFA provides robust security with minimal external dependency. SSO integration deferred to enterprise deployment phase.
2. **Distributed Job Brokers (Celery / Redis / RabbitMQ / Kafka)**:
   - *Rationale*: Monolithic PostgreSQL `FOR UPDATE SKIP LOCKED` transactional queue eliminates external broker failures, simplifies backup/restore, and reduces infrastructure overhead.
3. **Active Vulnerability Scanning & Fuzzing**:
   - *Rationale*: Strictly out of scope. The platform performs purely passive and non-invasive technical observation.
4. **Third-Party Vendor Questionnaires & Risk Acceptance**:
   - *Rationale*: Handled in upstream Third-Party Risk Management (TPRM) systems; platform focuses strictly on factual, verifiable technical evidence.
5. **Multi-Tenant Public SaaS Hosting**:
   - *Rationale*: Platform is deployed as an internal security tool within private network boundaries.

---

## 3. Operational Risk Register

| Risk ID | Category | Risk Description | Mitigating Architectural Control | Verification Story |
|---|---|---|---|---|
| **RSK-01** | Security | Server-Side Request Forgery (SSRF) / Cloud Metadata Probing | Custom DNS resolver with anti-rebinding IP pinning; blocking 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254, and IPv6 equivalents at network boundary. | Story 3.3 (NET-01, NET-02) |
| **RSK-02** | Security | Target Sandbox Egress Escape & Credential Access | Playwright browser runner runs unprivileged in isolated sandbox without database or master API credentials. | Story 4.2 (NET-02) |
| **RSK-03** | Data Integrity | Tenant Cross-Talk & Report Leakage | Scoped `ActorContext`, fine-grained object grants, and PostgreSQL Row-Level Security (RLS) policies on pooled connections. | Story 1.2, 1.3 (ACC-01, ACC-02) |
| **RSK-04** | Reliability | Worker Crash & Duplicate Result Submission | Transactional `FOR UPDATE SKIP LOCKED` claims, lease heartbeats, generation fencing (`generation_id`), and idempotency keys. | Story 2.1 (JOB-01, JOB-02) |
| **RSK-05** | Compliance | Expired Evidence Persistence | Scheduled daily purge job, UTC calendar-month expiration calculators with leap-year handling, and deletion journal replay for restored backups. | Story 7.1, 7.2 (RET-01, OPS-01) |
| **RSK-06** | Integrity | Inconsistent Bilingual Reporting | Common canonical JSON snapshot schema driving deterministic PDF generation for both English (`en`) and Swiss Standard German (`de-CH`). | Story 6.2, 6.3 (LNG-01, REP-01) |

---

## 4. Backlog Tracking & Implementation Milestones

- [x] **M0 — Project Foundation & Test Harness** (`docs/implementation/epic-00-foundation.md`)
- [ ] **M1 — Identity, Grants & Database RLS** (`docs/implementation/epic-01-access-control.md`)
- [ ] **M2 — Durable Job Queue & Quota Accounting** (`docs/implementation/epic-02-durable-jobs.md`)
- [ ] **M3 — Discovery, Scope Normalisation & Network Gate** (`docs/implementation/epic-03-discovery-network-gate.md`)
- [ ] **M4 — Host Verification & Required Enrichment** (`docs/implementation/epic-04-enrichment-adapters.md`)
- [ ] **M5 — Technical Workspace UI & Finding Annotations** (`docs/implementation/epic-05-workspace-ui.md`)
- [ ] **M6 — Evidence Storage & Bilingual Reporting** (`docs/implementation/epic-06-evidence-reporting.md`)
- [ ] **M7 — Data Retention, Lifecycle & Operations** (`docs/implementation/epic-07-lifecycle-operations.md`)
