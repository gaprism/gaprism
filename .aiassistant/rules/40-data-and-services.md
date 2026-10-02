---
apply: always
---

Service and data-layer rules:

Services:
- Put business rules into service modules
- Keep services cohesive and focused on a single responsibility
- Prefer explicit inputs and outputs
- Avoid hidden side effects
- Keep service functions testable

Data access:
- Keep database access out of templates
- Keep database access out of unrelated utility modules
- Avoid mixing persistence concerns with HTTP concerns
- Make transactions and side effects explicit where relevant

Transformation logic:
- Prefer deterministic transformation functions
- Keep mapping and normalization logic easy to test
- Avoid scattering the same transformation logic across routes, templates, and services

State and configuration:
- Avoid mutable global state
- Keep configuration access explicit and centralized
- Do not hide important behavior in import-time side effects