---
apply: always
---

Architecture guardrails for this Flask project:

Core structure:
- Use the Flask application factory pattern
- Register HTTP endpoints via Blueprints
- Keep Blueprints thin
- Route functions handle HTTP concerns only
- Business logic belongs in service modules
- Persistence logic belongs in models, repositories, or dedicated data-access helpers
- Templates must not contain business logic
- Utilities must stay generic and must not become a dumping ground for domain logic

Expected structure:
- app/
  - blueprints/
  - models/
  - service/
  - static/
  - templates/
  - utils/

Conventions:
- Preserve existing project structure unless there is a clear project-specific reason to extend it
- Avoid circular imports
- Avoid hidden coupling between Blueprints
- Keep request parsing close to the route
- Keep orchestration in routes or service-entry functions
- Keep reusable logic in services, not in routes or templates

Refactoring policy:
- Prefer localized refactors over broad rewrites
- Do not introduce a new architectural style unless explicitly requested
- Make the smallest change that fits the existing design
- For larger refactors, explain why the current design is insufficient and propose an incremental path