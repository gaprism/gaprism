---
apply: always
---

Testing and change discipline:

Testing:
- Add or update tests for non-trivial logic when tests exist in the project
- Prefer focused unit tests for service logic
- Prefer integration tests for route behavior when appropriate
- Keep tests readable and aligned with existing project patterns

Change scope:
- Do not modify unrelated files
- Do not rename files, modules, or symbols without a clear benefit
- Preserve public interfaces unless explicitly asked to change them
- Prefer backward-compatible changes by default

Code quality:
- Prefer readable, explicit control flow
- Keep functions small and cohesive
- Remove duplication only when the shared abstraction is actually simpler
- Avoid overengineering

Performance:
- Avoid obvious repeated work and N+1-style issues
- Do not prematurely optimize
- Mention performance tradeoffs when they materially affect the solution