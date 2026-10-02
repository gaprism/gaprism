---
apply: always
---

Authentication and identity rules:
- Respect existing Flask-Security-Too patterns
- Do not bypass existing auth flows
- Keep authentication concerns separate from business logic
- Be explicit about authorization checks
- Do not assume authentication implies authorization
- Preserve session and identity handling conventions already present in the project