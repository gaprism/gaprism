---
apply: always
---

Security and compliance guardrails:

General:
- Treat all external input as untrusted
- Validate and sanitize user input appropriately
- Never hardcode secrets, tokens, credentials, or private keys
- Prefer environment variables or existing secret-management mechanisms
- Do not expose stack traces, internals, or sensitive details to end users in production flows

Flask-specific:
- Respect authentication and authorization boundaries
- Preserve CSRF protections where relevant
- Be careful with redirects, file handling, template rendering, and serialization
- Escape output appropriately and avoid unsafe HTML rendering unless explicitly required
- Do not weaken existing security controls for convenience

Data protection:
- Minimize exposure of personal or sensitive data
- Do not log secrets or sensitive personal data
- Be careful with auditability and traceability when changing security-relevant code
- Prefer explicit permission checks over implicit assumptions

Operational safety:
- Fail clearly and intentionally
- Do not silently swallow exceptions
- Add logging where useful for operations and debugging, but keep logs safe
- When changing security-sensitive behavior, call out the risk explicitly