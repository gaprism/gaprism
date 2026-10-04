# Technical Due Diligence Platform — Implementation Specification

This directory contains the actionable Epics, Stories, and Definition of Done (DoD) specifications for the SaaS Technical Due Diligence Platform. It translates the design contracts in `/docs/design/` into strict, incremental milestones (M0 through M7).

---

## 1. Milestone Overview

| Milestone | Epic Specification | Core Deliverable | Primary Acceptance Gates |
|---|---|---|---|
| **M0** | [`epic-00-foundation.md`](epic-00-foundation.md) | Flask factory, config validation, locked dependencies, PostgreSQL test container | Independent instance configs, zero import side-effects, reproducible test harness |
| **M1** | [`epic-01-access-control.md`](epic-01-access-control.md) | Local authentication, MFA, workspace & assessment grants, DB RLS | ACC-01, ACC-02 (2-case access isolation, pooled DB context clearing) |
| **M2** | [`epic-02-durable-jobs.md`](epic-02-durable-jobs.md) | PostgreSQL `FOR UPDATE SKIP LOCKED` queue, leases, quota ledger | JOB-01, JOB-02, JOB-03 (Worker crash recovery, lease generation fencing) |
| **M3** | [`epic-03-discovery-network-gate.md`](epic-03-discovery-network-gate.md) | Scope normalisation, CT discovery paging, strict DNS SSRF gate | COL-01, NET-01, NET-02 (Public suffix rejection, anti-SSRF IP pinning) |
| **M4** | [`epic-04-enrichment-adapters.md`](epic-04-enrichment-adapters.md) | Live TLS validation, screenshot sandbox, GeoIP, Shodan, Web Risk | COL-02, PRV-01, FIND-01 (Explicit provider error classification, IP attribution) |
| **M5** | [`epic-05-workspace-ui.md`](epic-05-workspace-ui.md) | Jinja/HTMX host table, summary cards, analyst finding annotations | UX-01, PERF-01 (1,000-host pagination <200ms, optimistic locking on annotations) |
| **M6** | [`epic-06-evidence-reporting.md`](epic-06-evidence-reporting.md) | Private filesystem storage, frozen JSON snapshot, bilingual PDF (`en`/`de-CH`) | REP-01, REP-02, LNG-01, EVD-01 (Immutable snapshot hash, bilingual parity) |
| **M7** | [`epic-07-lifecycle-operations.md`](epic-07-lifecycle-operations.md) | 12-month calendar retention, daily purge, backup replay, operator runbooks | RET-01, OPS-01 (Calendar-month leap day clamping, backup restore purge replay) |

---


## Coding-agent model selection

The model shown in each story is the default for its remaining unchecked work. A story stays open until its Definition of Done is verified; the assignment is not evidence that the story is complete. Revalidate model availability before execution because ChatGPT, Codex, and API access are separate product boundaries.

The selection uses the lightest current model that fits the story's risk and coupling:

| Model | Default use in this plan | Reasoning baseline | ChatGPT/Codex Standard usage reference* |
|---|---|---:|---:|
| `gpt-6-luna` | Bounded, tool-verifiable implementation and mechanical work | `high` | 2.5 input / 12.5 output credits per 1M tokens |
| `gpt-6.1-sol` | Complex multi-file engineering; default for most stories | `medium` or `high` | 50 input / 250 output credits per 1M tokens |
| `gpt-6-astra` | Critical trust boundaries, ambiguous architecture, destructive lifecycle controls | `high` or `xhigh` | 250 input / 1,250 output credits per 1M tokens |

Note: Rates are the official Standard-speed ChatGPT/Codex credit references checked on 2026-10-02. Included subscription usage and model access depend on the workspace, seat, client, and sign-in method. Sources: [OpenAI model selection](https://developers.openai.com/api/docs/guides/model-selection), [ChatGPT/Codex pricing](https://learn.chatgpt.com/docs/pricing), and [workspace model availability](https://learn.chatgpt.com/docs/enterprise/workspace-model-availability).

Execution rules:

1. Start with the story's assigned model and reasoning effort. Do not select Astra merely because it is available.
2. Use the stated escalation rule only after a concrete failed acceptance test, unresolved security boundary, conflicting evidence, or material design ambiguity.
3. A stronger model does not relax review gates, tests, least privilege, or approval requirements.
4. Use Standard speed by default. Faster paid modes are justified only when elapsed time blocks delivery.
5. If the exact model is unavailable, pause model execution and select the closest enabled model in the same tier; record the substitution in the story or pull request.

## 2. Standard Story Structure

Every Story in this specification adheres to a uniform structure ensuring rigorous engineering quality and verifiable completion:

```markdown
### Story X.Y: [Story Title]
- **Coding-agent model**: Exact model ID and reasoning effort.
- **Price/performance rationale**: Why this is the lightest suitable model.
- **Escalation rule**: Concrete evidence that justifies a stronger model.
- **Goal**: Clear statement of the functional or technical objective.
- **Invariants Enforced**: Cross-cutting invariant IDs (e.g., INV-01, INV-06) maintained by this story.
- **Technical Contracts**: Detailed API routes, database models, class signatures, or algorithm behaviors.
- **Acceptance Criteria**: Verifiable functional behavior and negative security conditions.
- **Definition of Done (DoD)**:
  - [ ] Implementation complete in designated files.
  - [ ] Negative test cases and edge cases covered in Pytest.
  - [ ] Type checks pass (`mypy --strict`).
  - [ ] Linting & style pass (`ruff check`).
  - [ ] Acceptance criteria verified.
```

---

## 3. Shared Definition of Done (DoD) Framework

All Stories must satisfy the following shared baseline before being marked complete:

1. **Security & Boundary Isolation**:
   - No untrusted network access from backend workers without egress proxy screening (anti-SSRF).
   - No database credentials or tenant secrets exposed to runner sandboxes or client templates.
   - All dynamic SQL and RLS filters safely parameterized against SQL injection.
2. **Deterministic & Defensive Implementation**:
   - Explicit outcome typing (e.g., distinguishing `no_match`, `unlicensed`, `timeout`, and `error` per INV-04).
   - Append-only recording for technical observations; original facts are never overwritten in place.
   - Idempotent operations for all durable background tasks.
3. **Automated Testing & Code Quality**:
   - Unit and integration tests written using Pytest with synthetic fixtures.
   - Critical paths accompanied by negative adversarial test cases (e.g., expired TLS, DNS rebinding, malformed payloads).
   - Zero linter errors and 100% strict type conformance (`mypy --strict`).
4. **Documentation & Traceability**:
   - Relevant operational runbook updates where configuration or maintenance is affected.
   - Acceptance test ID and Invariant traceability documented.
