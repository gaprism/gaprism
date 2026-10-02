---
apply: always
---

UI and template guardrails:

Rendering model:
- Default to server-rendered Jinja templates
- Use HTMX for partial page updates and lightweight interactivity
- Use Tailwind CSS for styling
- Keep JavaScript minimal and focused
- Do not introduce SPA patterns or heavy frontend frameworks unless explicitly requested

Templates:
- Reuse the shared base template
- Respect existing template blocks such as header and content
- Keep templates focused on presentation
- Do not move domain decisions into Jinja
- Prefer template macros or reusable partials for repeated UI patterns

HTMX:
- Prefer HTMX for simple interactions, inline updates, form submissions, and partial refreshes
- Keep endpoints returning partial HTML small and focused
- Do not create unnecessary client-side state if server-rendered state is sufficient

Styling:
- Reuse existing Tailwind utility conventions and component patterns
- Prefer consistency with the current UI over inventing a new design language
- Keep markup readable and maintainable

Accessibility and UX:
- Preserve semantic HTML where practical
- Keep forms, buttons, labels, and navigation understandable
- Do not sacrifice clarity for cleverness