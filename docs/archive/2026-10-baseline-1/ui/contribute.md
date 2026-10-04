# Contributor guide

Status: engineering conventions plus an implemented synthetic design-system preview. Use [the design-system guide](design/design-system.md) for tested build/run commands and [validation evidence](design/design-system-validation.md) for current results. Production milestones remain planned.

Read every file in `rules/` and [the coding-agent index](README.md) before implementation. Use [architecture.md](architecture.md) for rationale and its linked design documents for precise contracts. Changes to trust boundaries, evidence semantics or sharing must update the owning document and explain their security impact.

## Proposed layout

```text
app/
  __init__.py              # Application factory
  extensions.py           # Unbound extension objects
  blueprints/             # HTTP parsing, authorisation and rendering
  models/                 # SQLAlchemy records and persistence helpers
  service/
    assessment/           # Scope and lifecycle
    discovery/            # CT normalisation and inventory
    checks/               # Typed provider adapters and interpretation
    access/               # Object grants and permission checks
    evidence/             # Artifact metadata, retention and storage interface
    reporting/            # Frozen snapshots and report lifecycle
    jobs/                 # Queue, leases, quotas and orchestration
  templates/              # Base layout, partials and safe report templates
  static/                 # Built local assets
  translations/           # Application-owned message catalogs
  utils/                  # Generic helpers only
runner/                   # Restricted target collection entry points
tests/                    # Unit, integration and isolated security fixtures
migrations/               # Reviewed Alembic changes
docs/                     # All project documentation
```

Use Python type hints, small functions and explicit inputs/outputs. Keep business rules out of routes and templates. Use Jinja, HTMX and Tailwind; user-facing strings use the chosen translation mechanism consistently. Choose and lock versions when implementation starts, after compatibility and security review.

Keep the product focused on technical verification. Do not introduce questionnaires, vendor-document uploads, contractual processor registers or supplier risk acceptance. Interpretation rules must be versioned, evidence-backed and separate severity from confidence. Optional analyst corrections preserve the source observation.

DE and EN report output is required; German uses Swiss Standard German. Use language-neutral stored identifiers and message catalogs for application-owned text, keeping UI locale separate from report locale. Full UI translations are a desirable enhancement. Test language variants for equivalent technical facts and rendered layout; preserve original provider evidence and label any explanatory translations. Never send confidential content to an external translation service by default.

IT Security owns operations. Phase 1 is non-critical, supports manual fallback and exports final reports for manual storage in TPRM. Do not add high-availability infrastructure or a TPRM connector without a concrete requirement. Keep reports portable and local retention independent of the authoritative TPRM copy.

Provider adapters return a typed observation envelope: subject, provider, observed/collected timestamps, execution status, verdict, confidence, evidence reference and adapter version. They do not decide who may read an assessment or whether a supplier is acceptable. Treat source data as untrusted; preserve source verification flags without overstating them.

Never run target probes from a web request or put target browsers on a credential-bearing application network. Do not add broad scanning, exploit checks or external submissions outside the agreed collection profile. No live third-party target is required for routine tests: use controlled fixtures and local adversarial targets in an isolated test network.

New entities and endpoints must have scope/permission tests, including report-only recipients. Test behaviour and security boundaries rather than mirroring implementation. Significant queue changes require crash/retry tests. Report changes require rendered-output inspection and evidence-link verification when report generation exists.

Phase 1 uses local team accounts; enterprise SSO is deferred. Preserve stable user IDs so future identity linking leaves ownership and grants intact. Artifact handling must use the storage interface rather than assume S3; the proposed initial backend is a private filesystem volume. Retention defaults to 12 configurable months. New retained record types must define their expiry clock, report dependencies, hold behaviour and deletion/restore tests.

Keep the codebase suitable for possible open sourcing in Phase 2: synthetic fixtures, external deployment configuration and preserved third-party notices. Source publication does not include team data or licensed provider results. Do not add public signup, customer tenancy or a publication workflow solely for this possibility.

Keep changes focused and backwards compatible. Record validation performed and limitations honestly. Do not modify an issued report or original observation to fix presentation: create a corrected version. Never include secrets or confidential supplier data in fixtures, screenshots, logs or issue examples.

Before merging implementation: review migrations, dependency changes, data exposure, permission checks and relevant tests. Destructive migrations and production access changes require explicit approval under the project instructions.

## Coding-agent workflow

1. Inspect the current implementation and identify the use case, owning module, invariant IDs and relevant acceptance tests. Do not assume the proposed layout already exists.
2. Choose the smallest change consistent with the contracts. If a real architectural choice arises, record its rationale, alternative, security effect and operational cost in the owning document.
3. Define inputs, result/error types, transaction boundary and authorisation before adding the route or worker. New persisted fields need scope, retention and migration semantics.
4. Implement the service/pure rule and focused tests; then connect the HTTP/template or job adapter. Test permission denials and failures at the actual boundary.
5. Update documentation and run relevant checks. Report actual results, fixture/live limitations and unresolved choices. Do not claim a plan or generated test proves production security.

## Concrete coding conventions

- New Python public interfaces use type hints and explicit return types. Prefer frozen value objects for commands/results; plain functions are sufficient for pure rules.
- Use `snake_case` functions/modules, `PascalCase` types and stable language-neutral status/rule IDs. Keep the project `app/service/` naming, not a new parallel `services/` tree.
- Ruff and strict mypy are configured in `pyproject.toml` and resolved by `uv.lock`. Run both for Python changes. Frontend build dependencies are resolved by `package-lock.json`; use frozen installs and review lockfile changes.
- Avoid implicit commits in repositories/model methods. Make the service entry point the transaction owner; nested services participate in the caller's transaction. Do not mix network calls and held DB locks.
- Do not pass SQLAlchemy entities across worker boundaries or into detached rendering jobs. Use serialised versioned IDs/DTOs and re-authorise/reload through scope checks.
- Use parameterised ORM/SQL expressions, allowlisted sort fields and bounded queries. JSONB is for versioned provider details, not a way to avoid relational ownership constraints.
- Inject clock/config/adapters at actual test boundaries. Avoid mutable global registries, service locators with hidden behaviour and generic abstraction frameworks.
- Catch known failures where they can be classified. Unexpected exceptions become explicit failed work with a correlation ID; do not log complete provider bodies or secrets.
- Keep Jinja macros/partials focused on presentation; use prepared view models. Avoid `safe` on collected content and do not build HTML inside provider adapters.
- Comments explain a non-obvious invariant or trade-off. Docstrings describe meaningful public contracts, not every trivial getter.

## Definition of done

A feature is complete when its authorised behaviour works, scoped negative cases pass, migrations/rights/expiry are accounted for, UI/report strings are catalogued, documents match the implementation and relevant acceptance evidence is recorded. Significant changes to identity, sharing, target networking, downloads or infrastructure require the deeper checks in [the implementation plan](design/implementation-plan.md).

Do not add tests that simply restate a dataclass or constant. Do add tests that can expose cross-case leakage, incorrect attribution, stale worker writes, partial-results mislabelling or alteration of issued evidence. Keep provider fixtures synthetic and label them. Runtime command documentation is added only after the commands exist and have been exercised.
