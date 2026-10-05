# Documentation

Start with [`CLAUDE.md`](../CLAUDE.md) in the repository root (commands, layout, rules). The documents below are read on demand, not all at once.

| Document | Read it when |
|---|---|
| [roadmap.md](roadmap.md) | You pick up a story: releases R0–R5, epics, acceptance criteria, definition of done |
| [checks-catalog.md](checks-catalog.md) | You build or change a check, a rule or a data source (free sources, limits, licences) |
| [rules.md](rules.md) | You change or review a rule: what each one flags, how serious, what it says (generated from the code, do not edit) |
| [export-format.md](export-format.md) | You read or change an export: the JSON structure, the CSV columns, the printable report, and what none of them say |
| [improvement-plan.md](improvement-plan.md) | You want to know why the code looks the way it does and what was kept, ported or replaced |
| [superpowers/specs/2026-10-04-mvp-restart-design.md](superpowers/specs/2026-10-04-mvp-restart-design.md) | You need the design: data model, execution model, security baseline, decisions D1–D13 |
| [archive/](archive/README.md) | You need history: the first plan (architecture, design contracts, epics M0–M7) |

## Conventions

- One topic per document. Update the catalogue row when a check ships and the roadmap when a story's scope changes.
- Decisions live in the spec (§6); do not bury them in stories.
- Prefer a short paragraph in the document that already owns the topic over a new document.
