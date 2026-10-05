# Web Due Diligence — project guide

Internal tool for security teams: enter a domain → discover hosts via Certificate Transparency → run technical checks per host → answer *Where is the data? Who processes it? How secure is the external posture?* Flask + Jinja/HTMX/Tailwind + PostgreSQL. Start with `docs/roadmap.md`; the doc index is `docs/README.md`.

## Commands (PowerShell, Python via uv)
- Install: `uv sync` · assets: `npm ci` then `npm run build`
- Tests: `uv run pytest` (unit + DB; `-m live` = real network, off by default) · lint: `uv run ruff check .` · types: `uv run mypy`
- DB: `uv run flask --app app db upgrade` · worker: `uv run flask --app app worker` · web: `uv run flask --app app run --debug`
- IP location data (offline, DB-IP Lite): `uv run flask --app app datasets update` (status: `datasets status`); stored in `var/datasets/`
- Rules and findings: `uv run flask --app app findings rules` (list) · `findings evaluate [--domain d]` (re-run on a finished scan) · `uv run python -m app.rules.docs` regenerates `docs/rules.md` (a test fails when it is stale)
- Config comes from `.env` (git-ignored; template `.env.example`): `DATABASE_URL`, `TEST_DATABASE_URL`, `DB_SCHEMA`, secrets, provider keys. Never print or commit keys.
- The dev database is shared and its role is restricted (no CREATEDB, `public` not writable): use `DB_SCHEMA`; tests create their own schema.

## Layout
- `app/`: factory, `config.py`, `models/`, `service/` (business logic), `checks/` (one module per check), `rules/` (pure: stored results in, findings out), `blueprints/` (thin routes), `templates/`, `static/`, `translations/`
- `runner/`: the network boundary — SSRF-safe DNS, IP-pinned HTTP client, TLS prober. **All target-facing traffic goes through it.**
- `assets/`: Tailwind source (compiles to `app/static/css`) · `migrations/`: Alembic · `tests/` · `docs/`

## Rules that matter
1. Typed outcomes: `ok | no_data | unavailable | error | skipped`. Never show "clean" for "not checked".
2. Every fact carries subject, source and timestamp. A CT name is not a live host; an IP is not a hostname attribution.
3. Everything is bounded (hosts, bytes, time, concurrency, retries). No side effects at import time.
4. Routes are thin, logic lives in `service/`, templates only present. Escape everything; no `|safe` on collected data.
5. A new check = one module in `app/checks/` + one test with fixtures (no network) + one row in `docs/checks-catalog.md`. A new rule = one function in `app/rules/` + a test in `tests/rules/` fed with the real check's output + regenerate `docs/rules.md`. Having no findings is not "clean": the pages say what the rules could not see.
6. Unit tests never touch the network; mark real-network tests `@pytest.mark.live`.
7. Provider keys only from the environment; logs redact `key=`, `token=` and `Authorization`.
8. Security-boundary changes (egress, auth, SQL) get a short review note in the commit message.

## Process
- Small vertical slices (stories `S*.*` in the roadmap); one commit per story on branch `mvp`; ask before pushing.
- Strings in templates and flash messages go through `_()`; English first, de-CH later.
- UI uses the existing design tokens (`assets/tokens.css`, `assets/app.css`); rebuild the CSS after template changes.
