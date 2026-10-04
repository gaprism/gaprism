# Epic 01: Identity, Grants & Database RLS (Milestone M1)

**Epic Owner**: Security & Authorisation  
**Target Milestone**: M1 Private Workspace  
**Status**: In progress  
**Key Invariants Enforced**:
- **INV-01**: A role never grants access to an unrelated assessment.
- **INV-02**: Report-only access never grants underlying case, job, host, or raw-artifact access.
- **INV-09**: Access expires at the policy deadline even if physical deletion is delayed.

---

## 1. Epic Overview

The objective of Epic 01 is to implement a robust, defense-in-depth access control architecture combining application-level RBAC, object-level assessment and report grants, and PostgreSQL Row-Level Security (RLS). This ensures that analysts, reviewers, viewers, and report recipients operate within strictly segregated boundaries, and connection pooling never leaks tenant data.

---

## 2. Stories Breakdown

### Story 1.1: Local Authentication & MFA Setup
- **Coding-agent model**: `gpt-6-sol` with reasoning effort `high`.
- **Price/performance rationale**: Authentication, MFA, rate limiting, session invalidation, and enumeration resistance form a high-impact trust boundary with several interacting failure modes.
- **Escalation rule**: Use `gpt-6.1-sol` (`high`) for mechanical templates and tests, but retain sol for design, implementation review, and negative security cases.
- **Goal**: Implement invitation-only local user accounts, password hashing, rate limiting, and mandatory TOTP MFA via Flask-Security-Too.
- **Invariants Enforced**: INV-01
- **Technical Contracts**:
  - `app/blueprints/auth/`:
    - `/login`, `/logout`, `/change-password`, `/tf-setup` (TOTP enrollment), `/tf-validate`.
    - Public self-registration is explicitly disabled (`SECURITY_REGISTERABLE = False`).
    - Password hashing using Argon2id or bcrypt with strong work factors.
    - TOTP secrets encrypted with injected key (`MFA_ENCRYPTION_KEY`).
  - CLI Command `flask users create-admin`:
    - Prompts interactively for admin email and password without logging.
  - Rate limiting on authentication routes (maximum 5 failed attempts per IP/user per 15-minute window).
- **Acceptance Criteria**:
  - An account without completed TOTP MFA cannot access any protected workspace routes.
  - Failed login attempts do not disclose whether an email exists in the system (constant response timing).
  - Deactivating a user immediately invalidates active sessions and TOTP authentication tokens.
- **Definition of Done (DoD)**:
  - [ ] Auth blueprint and templates implemented.
  - [ ] CLI admin bootstrap command operational.
  - [ ] Unit and integration tests covering login, MFA flow, lockout, and session revocation in `tests/auth/`.
  - [ ] Type checks pass (`mypy --strict app/blueprints/auth/`).

---

### Story 1.2: Workspace & Assessment Object Grants
- **Coding-agent model**: `gpt-6-sol` with reasoning effort `high`.
- **Price/performance rationale**: Object grants, workspace isolation, report-only access, expiry, and four-eyes controls require exact policy reasoning across application and data layers.
- **Escalation rule**: Delegate repetitive access-matrix test expansion to `gpt-6-luna` (`high`); sol owns the permission semantics and final review.
- **Goal**: Implement `ActorContext`, permission evaluation service, and granular assessment and report grants.
- **Invariants Enforced**: INV-01, INV-02, INV-09
- **Technical Contracts**:
  - `app/service/access/context.py`:
    - `ActorContext(user_id: UUID, workspace_id: UUID, auth_freshness: datetime, correlation_id: str)` constructed from verified session.
  - `app/models/grant.py`:
    - `AssessmentGrant(assessment_id, user_id, role: ['owner', 'analyst', 'reviewer', 'viewer'], can_download: bool, expires_at: datetime | None)`.
    - `ReportGrant(report_version_id, user_id, can_download: bool, expires_at: datetime | None)`.
  - `app/service/access/permission_evaluator.py`:
    - `check_permission(actor: ActorContext, target: Assessment | ReportVersion, action: ActionEnum) -> bool`.
    - Two-case access matrix: `owner`, `analyst`, `reviewer`, `viewer`, `report_only`, `admin_without_grant`.
    - Admin without explicit grant receives HTTP 404/403 on case contents.
- **Acceptance Criteria**:
  - Users cannot access assessments in other workspaces or assessments in their workspace without a grant.
  - Report-only recipients can only access the exact report version specified and cannot access raw case, host, or artifact data (INV-02).
  - Expired grants immediately deny access even if the database row has not yet been purged (INV-09).
  - Four-eyes review rule: Approver must be distinct from the preparer when `FOUR_EYES_ENABLED` is active.
- **Definition of Done (DoD)**:
  - [x] Models and permission service implemented.
  - [x] Test matrix **ACC-01** verified across 2 cases and 5 user roles in `tests/access/test_matrix.py`.
  - [x] Strict type checking passes (`mypy --strict app/service/access/`).

---

### Story 1.3: PostgreSQL Row-Level Security Policies
- **Coding-agent model**: `gpt-6-sol` with reasoning effort `xhigh`.
- **Price/performance rationale**: RLS is a last-line tenant boundary; recursive policies, owner bypass, pooled-session leakage, and runtime-role privileges require the strongest reasoning tier.
- **Escalation rule**: Do not downgrade the policy design or adversarial review. Sol may implement already-approved, isolated SQL edits under sol review.
- **Goal**: Write and apply SQL RLS policies on `assessment`, `host`, `check_result`, and `artifact` tables with transactional context setting.
- **Invariants Enforced**: INV-01, INV-02
- **Technical Contracts**:
  - `migrations/versions/*_rls_policies.py`:
    - Enable RLS on core tables: `ALTER TABLE assessment ENABLE ROW LEVEL SECURITY;`.
    - Web session parameters: `app.user_id`, `app.workspace_id`. The coordinator's
      job-scoped `app.job_id` context is delivered with Story 2.2 before a coordinator
      runtime role receives write privileges.
    - SQL Policies:
      - `assessment_policy`: `workspace_id = current_setting('app.workspace_id')::uuid AND EXISTS (SELECT 1 FROM assessment_grant WHERE ...)`
      - `report_policy`: `EXISTS (SELECT 1 FROM report_grant WHERE ...)`
  - `app/service/access/rls.py`:
    - Context manager `set_transaction_actor(db_session, actor: ActorContext)` executing `SET LOCAL app.user_id = ...; SET LOCAL app.workspace_id = ...;`.
    - Auto-reset / cleanup on session release back to the pool.
- **Acceptance Criteria**:
  - Direct SQL queries executed without `SET LOCAL` return 0 rows.
  - Reusing a connection from connection pool with switched user context never leaks rows from previous tenant (**ACC-02**).
  - Web runtime DB role lacks `BYPASSRLS` privileges and cannot alter policies.
  - The migration owner has `BYPASSRLS` (or superuser) solely to own the fixed-search-path,
    non-dynamic `SECURITY DEFINER` policy helpers; it is never used by the application.
- **Definition of Done (DoD)**:
  - [x] Alembic migration creating RLS policies for every table present through migration
    `0005`; future artifact migrations must apply the same policy-helper contract.
  - [x] Integration tests **ACC-02** verifying pooled connection reuse against a real PostgreSQL instance in `tests/access/test_rls.py`.
  - [x] The tested web runtime role is `NOSUPERUSER NOBYPASSRLS`, cannot alter RLS, and
    receives access only through reviewed helper execution and table privileges.

#### Verification evidence and deferred schema dependency

Migration `0005_harden_rls_policies` removes recursive grant lookups and the former
workspace-admin content bypass. Its `SECURITY DEFINER` helpers derive the actor from
transaction-local settings, use a fixed `search_path`, disable row-security fallback,
contain no dynamic SQL, and have `PUBLIC` execution revoked. ACC-02 verifies missing
context, admin-without-grant, case/host/check isolation, owner versus recipient grant
visibility, nested context restoration, pooled actor switching, and runtime-role attributes.

The `artifact` table is intentionally not present before Epic 06. Story 6.1 must add its
RLS policy using these helpers and extend ACC-02 before granting runtime access. Coordinator
write policies remain fail closed until Story 2.2 introduces validated job and lease context.
