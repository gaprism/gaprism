---
apply: always
---

Default response format for this project:

For bug fixes:
1. State the root cause briefly
2. State whether the proposed fix fits the current architecture
3. Provide the recommended code change
4. Mention impacted files
5. Mention relevant risks or follow-up only when necessary

For new features:
1. State the implementation approach
2. Explain how it fits the current Flask architecture
3. Provide file-by-file changes
4. Prefer complete code blocks over fragments when practical
5. Keep explanations concise and useful

For reviews:
- Prioritize findings by importance
- Distinguish must-fix from nice-to-have
- Call out correctness, security, maintainability, and test gaps clearly

Behavior:
- Prefer one strong recommendation over many alternatives
- Flag uncertainty explicitly instead of guessing
- Prefer minimal diffs over broad rewrites
- Keep explanations short unless deeper explanation is clearly needed