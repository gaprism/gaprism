---
apply: always
---

Unless explicitly requested, do not do the following:
- Introduce a heavy frontend framework
- Introduce Celery, Redis, Kafka, GraphQL, or a microservice split
- Move business logic into routes
- Move business logic into Jinja templates
- Hide important tradeoffs
- Use mutable global state
- Add new dependencies when the standard library or current dependencies are sufficient
- Rewrite large files when a focused patch is enough
- Replace project-specific patterns with generic patterns without clear benefit
- Produce pseudo-code when real code is feasible