# Documentation

Start with [`CLAUDE.md`](../CLAUDE.md) in the repository root (commands, layout, rules); contributors also read [`CONTRIBUTING.md`](../CONTRIBUTING.md). The documents below are read on demand, not all at once.

| Document | Read it when |
|---|---|
| [checks-catalog.md](checks-catalog.md) | You build or change a check, a rule or a data source (free sources, limits, licences) |
| [rules.md](rules.md) | You change or review a rule: what each one flags, how serious, what it says (generated from the code, do not edit) |
| [export-format.md](export-format.md) | You read or change an export: the JSON structure, the CSV columns, the printable report, and what none of them say |
| [translation.md](translation.md) | You add or change a sentence of the interface, or translate it: how a sentence is written, the commands, what the tests refuse |
| [translation-glossary.md](translation-glossary.md) | You write German text: the voice, the spelling and the one name of each term |
| [deploy.md](deploy.md) | You run it with Docker Compose: quickstart, HTTPS and reverse proxies, upgrades, backups, what is hardened and what is left to you |
| [deploy-render.md](deploy-render.md) | You give colleagues a test installation on Render's free tier with a Neon database: the Blueprint, accounts, limits, what to tell the testers |
| [superpowers/specs/2026-10-04-mvp-restart-design.md](superpowers/specs/2026-10-04-mvp-restart-design.md) | You need the design: data model, execution model, security baseline, decisions D1–D13 |
| [archive/](archive/README.md) | You need history: the first plan (architecture, design contracts, epics M0–M7) and [the review that led to the restart](archive/2026-10-baseline-1/improvement-plan.md) (what was kept, ported or replaced) |

## Conventions

- One topic per document. Update the catalogue row when a check ships.
- Decisions live in the spec (§6); do not bury them in stories.
- Prefer a short paragraph in the document that already owns the topic over a new document.
