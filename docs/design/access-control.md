# Identity, permissions and database isolation

Owner: authorisation contract for web, workers and downloads. See [data model](data-model.md) and [evidence/reporting](evidence-reporting.md). The purpose is private team work with deliberate sharing, not customer multi-tenancy.

## 1. Authentication and actor context

Use Flask-Security-Too's supported identity/session/MFA mechanisms for the selected version; no home-grown password hashing, TOTP algorithm or reset-token implementation. Bootstrap one administrator through an operator-only command that prompts for secrets without logging them. Disable public registration; administrators invite team members through expiring, single-use tokens. Rate-limit login, invitation acceptance, reset and MFA attempts; keep responses from revealing whether an account exists.

Require an active local account and workspace membership. Complete MFA enrolment before granting normal application access. Encrypt recoverable MFA secrets using a dedicated injected key; hash recovery codes. Recovery must not silently downgrade accounts to password-only access. Secure/HttpOnly/SameSite cookies, HTTPS, CSRF and session revocation on reset/deactivation are baseline controls. Do not store case permissions solely in a long-lived session cookie; resolve current grants on each request/use case.

An `ActorContext` contains internal user ID, workspace ID, authentication freshness and correlation ID. Build it from the validated session and DB membership. Ignore client-supplied actor/workspace ownership fields. Administrators are not content superusers. Enabling SSO later links issuer+subject to stable IDs through an explicit account-linking process, without rewriting case ownership.

Authentication decorators alone do not establish object access. Apply authentication and the common service permission check, including jobs triggered through CLI. [Flask-Security patterns](https://flask-security-too.readthedocs.io/en/stable/patterns.html).

## 2. Effective permission matrix

`D` means only when the current grant's explicit `can_download` is true. `V` means only the exact issued report version and its frozen report-owned artifacts. The server checks the same policy whether a control is visible in the UI or called directly.

| Operation | Owner | Analyst | Reviewer | Viewer | Report-only recipient | Admin without case grant |
|---|---|---|---|---|---|---|
| Read case/run/hosts/results | Yes | Yes | Yes | Yes | No | No |
| Read source evidence/thumbnail | Yes | Yes | Yes | Yes | No | No |
| Download source evidence | D | D | D | D | No | No |
| Start/cancel case scans | Yes | Yes | No | No | No | No |
| Add technical annotation | Yes | Yes | Yes | No | No | No |
| Prepare report draft | Yes | Yes | No | No | No | No |
| Read draft reports | Yes | Yes | Yes | Yes | No | No |
| Approve report | Yes* | No | Yes* | No | No | No |
| Issue report | Yes | No | No | No | No | No |
| Read issued case reports | Yes | Yes | Yes | Yes | V | No |
| Download issued report/evidence package | D | D | D | D | D + V | No |
| Manage case or report grants | Yes | No | No | No | No | No |
| Record TPRM handoff | D | D | No | No | No | No |
| Manage team/provider configuration | Only if admin | Only if admin | Only if admin | Only if admin | Only if admin | Yes |

*If mandatory four-eyes review is enabled, the approver must differ from the preparer. Owners are not exempt. Owner issue permission remains distinct from independent approval. Default `can_download`: true for owner/analyst/reviewer; false for viewer/report-only recipient until expressly granted. The UI must not suggest that disabling download prevents screenshots or copying visible data; it controls platform export endpoints.

Case grants grant access to reports belonging to that case. Exact-version report grants add a narrower independent access path. Revoking a report-only grant does not remove access obtained through an active case grant; show effective access sources in the sharing UI. Revoking a case grant does not implicitly erase intentionally separate report grants: offer the owner an explicit option to revoke both and preview the effect. Deactivating a user/membership denies all paths.

The owner can share only with existing active members of the same workspace. A report grant requires an issued version and may not outlive that report. No wildcard version grants or anonymous share links. A report-only recipient may not infer the case ID through navigable URLs or access the case title/metadata beyond what was intentionally frozen into the report.

## 3. Authorisation algorithm

For every use case:

1. Establish active actor/workspace membership from trusted authentication context.
2. Resolve the object inside the actor's workspace using scoped queries; inaccessible and missing IDs yield the same 404 response.
3. Check visibility and policy expiry. A retained-but-expired artifact is not ordinarily readable, even before purge runs.
4. Compute current effective grants and check the specific operation. Visible objects with an unavailable action return 403.
5. Validate reference scope for all submitted child IDs; never allow a host/finding/artifact from another case or run.
6. For sensitive writes, require recent MFA and recheck under the short state/grant transaction before commit.
7. Record security-relevant writes atomically. Downloads record an access event before streaming, without claiming successful reading or completed TPRM transfer.

Permissions are not cached across requests initially. UI visibility is a convenience, not the enforcement point. An in-flight download can continue after revocation; revocation blocks subsequent requests. Do not promise retrieval of previously downloaded copies.

## 4. RLS design and database roles

RLS is defence in depth, not an identity system. The web app remains trusted to bind the authenticated actor to transaction context. A compromised application/DB administrator can exceed this model; runner isolation reduces that exposure. PostgreSQL owners and `BYPASSRLS` roles can bypass ordinary policies, so runtime ownership and role attributes matter. [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

| DB identity | Intended authority |
|---|---|
| Schema migration owner | DDL, policy and grant changes during controlled deployment; not used by app/worker |
| Web runtime | Scoped CRUD through policies; cannot change RLS, roles, source observations or issued artifact bytes |
| Coordinator runtime | Claim jobs and write observations for leased work through job-scoped policies/entry points; cannot administer users or grants |
| Retention operator | Purpose-limited expiry/deletion/hold bookkeeping under the approved policy; no interactive normal-user path |
| Backup operator | Explicit backup/restore authority, separately protected; complete backup verification |

Begin each transaction with trusted `app.user_id`, `app.workspace_id` and, for worker paths, validated job context using parameterised transaction-local settings. Missing or malformed context denies access. Reset/rollback before returning pooled connections; test connection reuse between two users. Never accept a context setting from a query parameter/header.

Policy families:

- Case records: workspace equality AND active membership AND effective case grant AND applicable access expiry. Read and write predicates differ by role/operation.
- Grant records: users may inspect their own grant; only owner policy paths may create/change case/report grants. Grant creation must not let a caller manufacture an owner grant to an unrelated case.
- Report-version records: authorised case read OR an active exact-version report grant, with issued-state restriction on the latter.
- Report artifacts: follow only the owning report version's policy; case artifacts follow case policy. No policy joins via `source_artifact_id` to expand recipient access.
- Source observation inserts: validated active job context with exact scope and lease generation; normal users annotate separate tables instead.
- Issued snapshot/rendering updates: prohibited under ordinary runtime roles except narrowly defined lifecycle/expiry fields. Prefer constrained operations over a broad model update endpoint.

Avoid recursive RLS when policies consult grant/membership tables. Keep the lookup path small: a dedicated, reviewed helper can read access metadata using an owner without table ownership over evidence. If a `SECURITY DEFINER` helper is necessary, fix its `search_path`, schema-qualify objects, revoke public execution, use no dynamic SQL and derive the actor from validated transaction context rather than a caller-chosen user ID. Grant helper execution only to intended roles and test it directly. Include the actual SQL policies/functions in migrations, not only Python checks.

The implemented policy helpers are owned by the controlled migration identity. That identity
must have `BYPASSRLS` (or be a superuser during local disposable tests) because the protected
tables use `FORCE ROW LEVEL SECURITY`; it must never be the web or coordinator login. Helper
execution is revoked from `PUBLIC` and must be granted explicitly to each provisioned runtime
role together with only the table operations that role needs. A deployment must fail rather
than changing the helper owner to the web runtime role or granting that role `BYPASSRLS`.

The job queue needs cross-case claim ability without cross-case interactive browsing. Expose a narrowly scoped queue claim operation to the coordinator; return only required job metadata. Data access for execution must validate current job ID/lease owner/generation and scope. Do not solve worker access by giving the entire coordinator `BYPASSRLS`. The trusted coordinator still handles provider credentials; the browser/collector process does not connect to PostgreSQL at all.

## 5. Privileged changes and audit

Audit login/MFA/recovery outcomes, user deactivation, grant creation/change/revocation, owner transfer, scan scope/cancellation, report approval/issue/download, handoff confirmation, provider-rights changes, hold changes and deletion. Metadata is allowlisted: IDs, status codes, counts and policy hashes; no passwords, MFA tokens, cookies, headers or full collected page text. Use UTC timestamps and correlation IDs.

Application audit rows cannot prove integrity against an infrastructure operator. Support protected audit export separately from ordinary content access. Exceptional ownership recovery after an owner leaves is an IT Security operation with a reason and audit trail, not an admin button that reveals all cases. Require deliberate scope and current authenticated operator identity. Deactivation always takes immediate effect; orphaned ownership is an operational recovery task, not a reason to leave an account enabled.

## 6. Mandatory negative cases

Test with owner A, analyst B, viewer C, report-only D and admin E without content grants. Use at least two cases and two report versions. Deny: guessed IDs; cross-case children; source screenshot via report grant; later-version access; expired user/grant/artifact; stale pooled context; direct mutation by viewer; self-approval under four-eyes; report issue after approval-invalidating edit; cross-workspace invites; unauthorised grant escalation; DB runtime owner bypass; coordinator writes after lease loss. Test full pages, HTMX, search/counts, thumbnails and streaming handlers, not only one service function.
