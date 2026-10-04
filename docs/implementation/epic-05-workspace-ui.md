# Epic 05: Technical Workspace & Annotation UI (Milestone M5)

**Epic Owner**: Frontend & Analyst Workspace  
**Target Milestone**: M5 Technical Workspace  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-03**: Every collected fact identifies its subject, source, time, and collection method.
- **INV-04**: No data, no match, not licensed and collection failure are distinct outcomes.

---

## 1. Epic Overview

The objective of Epic 05 is to build a responsive, server-rendered web interface using Jinja2 templates, HTMX for dynamic asynchronous updates, and Tailwind CSS. It provides analysts with an Overview dashboard, real-time scan progress indicators, a high-performance paginated host inventory, and an optimistic-locking technical finding annotation workflow.

---

## 2. Stories Breakdown

### Story 5.1: Assessment Overview & Summary Cards
- **Coding-agent model**: `gpt-6-luna` with reasoning effort `high`.
- **Price/performance rationale**: The overview and summary cards are scoped UI work with an approved design system and concrete HTMX/test contracts.
- **Escalation rule**: Escalate to `gpt-6.1-sol` (`medium`) for query aggregation, accessibility, or state-synchronisation issues spanning several layers.
- **Goal**: Render the Assessment Overview screen featuring Location, Provider Dependencies, and Security Signal summary cards with live HTMX scan progress updates.
- **Invariants Enforced**: INV-03, INV-04
- **Technical Contracts**:
  - `app/blueprints/assessments/views.py`:
    - `GET /assessments/<uuid:id>`: Renders overview dashboard.
    - `GET /assessments/<uuid:id>/progress`: HTMX polling endpoint returning run progress partial (active jobs, discovered hosts count, status badges).
  - Summary Cards:
    - **Location**: Breakdown of observed hosting countries (ISO flags/codes) with explicit disclaimer ("Observed public IP location, not contractual data storage guarantee").
    - **Providers**: Observed CDNs, DNS providers, and cloud hosting platforms.
    - **Security Signals**: Aggregate counts of verified TLS certificates, open ports, missing HTTP security headers, and observed CVEs.
  - HTMX Polling: Triggers `hx-get="/assessments/<id>/progress"` every 2 seconds while run status is `running` or `queued`; halts upon reaching terminal status (`completed`, `partial`, `cancelled`, `failed`).
- **Acceptance Criteria**:
  - Overview cards display verified structured facts and explicit limitations without unverified risk judgements.
  - Real-time progress updates cleanly via HTMX partial swaps without requiring full page reloads.
  - HTMX polling stops automatically when the scan finishes.
- **Definition of Done (DoD)**:
  - [ ] Jinja templates and HTMX partials implemented in `templates/assessments/`.
  - [ ] Blueprint route tests in `tests/ui/test_overview.py`.
  - [ ] Frontend responsiveness verified with zero JavaScript console errors.

---

### Story 5.2: Searchable Host Inventory Table
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Database pagination, filtering, sorting, 1,000-host performance, and accessible interaction require coordinated backend and UI changes.
- **Escalation rule**: Use Luna for isolated template refinements; escalate to Astra only if access isolation and query planning conflict.
- **Goal**: Implement a paginated, filterable host table capable of sorting and searching 1,000 hosts with sub-200ms latency and full keyboard navigation.
- **Invariants Enforced**: INV-03
- **Technical Contracts**:
  - `app/blueprints/assessments/views.py`:
    - `GET /assessments/<uuid:id>/hosts`:
      - Query params: `page`, `per_page` (default 50, max 100), `q` (hostname substring), `country` (ISO code), `provider`, `tls_status` (`valid`, `invalid`, `expired`, `untested`), `severity` (`informational`, `low`, `medium`, `high`, `critical`).
      - Keyset or bounded offset pagination with SQL index optimization (`CREATE INDEX idx_host_assessment_lookup ON host (assessment_id, hostname);`).
  - `templates/assessments/partials/host_table.html`:
    - Keyboard navigation support (`tabindex`, arrow navigation, ARIA landmarks) (**UX-01**).
    - Host details modal/drawer showing TLS cert chain, DNS records, Shodan ports, and screenshot thumbnails with safe escaping.
- **Acceptance Criteria**:
  - 1,000-host test fixture queries and renders within 200ms (**PERF-01**).
  - Full search, filter, and host inspection workflow is operable entirely via keyboard (**UX-01**).
  - All target-supplied strings (hostnames, headers, banners) are safely HTML-escaped.
- **Definition of Done (DoD)**:
  - [ ] Host inventory routes and templates implemented.
  - [ ] Playwright accessibility and keyboard test **UX-01** passing in `tests/ui/test_accessibility.py`.
  - [ ] Performance benchmark test **PERF-01** passing in `tests/performance/test_host_table.py`.

---

### Story 5.3: Finding Revision & Annotation Engine
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Optimistic concurrency, immutable observations, validation, and authorisation make this more than a simple form implementation.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if append-only revision history or concurrent insert semantics remain ambiguous.
- **Goal**: Implement optimistic-locking annotation forms allowing analysts to flag false positives or provide technical context without overwriting original observations.
- **Invariants Enforced**: INV-03, INV-07
- **Technical Contracts**:
  - `app/models/annotation.py`:
    - `FindingAnnotation`: `id`, `finding_id`, `assessment_id`, `author_id`, `justification`, `revised_severity`, `is_false_positive: bool`, `version_id: int`, `created_at`, `updated_at`.
  - `app/service/assessment/annotation.py`:
    - `create_or_update_annotation(finding_id: UUID, data: AnnotationSchema, expected_version: int, actor: ActorContext) -> FindingAnnotation`:
      - Validates `expected_version` matches existing `version_id`.
      - On mismatch, raises `OptimisticLockConflictError` and returns HTTP 409.
      - Appends revision history; original automated check result rows remain immutable (INV-03, INV-07).
- **Acceptance Criteria**:
  - Adding an annotation preserves original check results and records author, timestamp, and revision reason.
  - Concurrent edits with outdated version IDs are rejected with HTTP 409 conflict and clear UI warning.
- **Definition of Done (DoD)**:
  - [ ] Annotation models and services implemented.
  - [ ] Optimistic locking conflict tests passing in `tests/assessments/test_annotation.py`.
  - [ ] Type checks pass (`mypy --strict app/service/assessment/annotation.py`).
