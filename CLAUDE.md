# Gaprism — project guide

Internal tool for security teams: enter a domain → discover hosts via Certificate Transparency → run technical checks per host → answer *Where is the data? Who processes it? How secure is the external posture?* Flask + Jinja/HTMX/Tailwind + PostgreSQL. Start with the doc index, `docs/README.md`.

## Commands (PowerShell, Python via uv)
- Install: `uv sync` · assets: `npm ci` then `npm run build`. Declared dependencies are what the code imports (`tests/test_dependencies.py`); add one with `uv add`, and stop the worker and the web first: on Windows `uv sync` cannot replace a compiled package a running process has loaded (`markupsafe`) and a failed run leaves `.venv` half-installed (repair: rename the locked `.pyd` aside, then `uv sync --reinstall-package <name>`)
- Tests: `uv run pytest` (unit + DB; `-m live` = real network, off by default) · lint: `uv run ruff check .` · types: `uv run mypy`
- DB: `uv run flask --app app db upgrade` · worker: `uv run flask --app app worker` · web: `uv run flask --app app run --debug`
- IP location data (offline, DB-IP Lite) and exploitation data (CISA KEV, EPSS; they rank the CVEs of the ports check): `uv run flask --app app datasets update` (status: `datasets status`); stored in `var/datasets/`
- Accounts: `uv run flask --app app users --help` (create-admin, create, invite, reset-link, list, set-password, deactivate, activate, grant-admin, revoke-admin, reset-mfa); assessments are private or shared with everyone signed in (owner and admins decide)
- Audit log: `uv run flask --app app audit list [--days N] [--group g] [--user text]` (administrators also read `/audit/`); limits `MAX_SCANS_PER_USER_PER_HOUR`, `MAX_HOSTS_PER_RUN` (ceiling 2000), `AUDIT_RETENTION_DAYS`
- After pulling or switching branches run `db upgrade` on the dev schema (the worker's housekeeping fails on a table the schema lacks)
- Docker: `docker compose up -d --build` (db, web, worker; `--profile proxy` adds HTTPS) · one-off commands `docker compose run --rm cli flask …` · see `docs/deploy.md`; the image installs gunicorn from the `deploy` dependency group, and `TRUSTED_PROXY_COUNT` says how many reverse proxies stand in front
- Demo for colleagues on Render's free tier with a Neon database: `render.yaml` + `deploy/render-start.sh`, steps and limits in `docs/deploy-render.md` (the image installs the data at build with `BAKE_DATASETS=1`; accounts are created from your machine with the service's `SECURITY_PASSWORD_SALT`)
- Rules and findings: `uv run flask --app app findings rules` (list) · `findings evaluate [--domain d]` (re-run on a finished scan) · `uv run python -m app.rules.docs` regenerates `docs/rules.md` (a test fails when it is stale)
- Translations (German as written in Switzerland, `de_CH`): `uv run python scripts/translations.py update` (read the source, write `app/translations/messages.pot`, bring `de_CH/LC_MESSAGES/messages.po` in step) · `status` · `compile` (the `.mo`); all three kinds of file are committed; how a sentence is written and the tests that refuse a stale or careless catalogue are in `docs/translation.md`, the voice and the terms in `docs/translation-glossary.md`
- Style guide (tokens, type, icons and the real components on one static page; not a route): `uv run python scripts/styleguide.py [folder]` writes `var/styleguide/index.html` with its own copy of the stylesheet, fonts and logos, so the folder opens from disk or can be handed over; run `npm run build` first after changing `assets/` or a template (a test fails when the page uses a class the stylesheet lacks, or leaves out a token, tone, button variant or icon)
- Config comes from `.env` (git-ignored; template `.env.example`): `DATABASE_URL`, `TEST_DATABASE_URL`, `DB_SCHEMA`, secrets, provider keys. Never print or commit keys.
- The dev database is shared and its role is restricted (no CREATEDB, `public` not writable): use `DB_SCHEMA`; tests create their own schema.

## Layout
- `app/`: factory, `config.py`, `models/`, `service/` (business logic), `checks/` (one module per check), `rules/` (pure: stored results in, findings out), `blueprints/` (thin routes), `templates/`, `static/`, `translations/`
- `runner/`: the network boundary — SSRF-safe DNS, IP-pinned HTTP client, TLS prober. **All target-facing traffic goes through it.**
- `assets/`: Tailwind source (compiles to `app/static/css`) and the style-guide page `styleguide.html` (its classes are compiled in; the page itself is no part of the app) · `scripts/` · `migrations/`: Alembic · `tests/` · `docs/`

## Rules that matter
1. Typed outcomes: `ok | no_data | unavailable | error | skipped`. Never show "clean" for "not checked".
2. Every fact carries subject, source and timestamp. A CT name is not a live host; an IP is not a hostname attribution.
3. Everything is bounded (hosts, bytes, time, concurrency, retries). No side effects at import time.
4. Routes are thin, logic lives in `service/`, templates only present. Escape everything; no `|safe` on collected data.
5. A new check = one module in `app/checks/` + one test with fixtures (no network) + one row in `docs/checks-catalog.md`. A new rule = one function in `app/rules/` + a test in `tests/rules/` fed with the real check's output + regenerate `docs/rules.md`. Having no findings is not "clean": the pages say what the rules could not see.
6. Unit tests never touch the network; mark real-network tests `@pytest.mark.live`.
7. Provider keys only from the environment; logs redact `key=`, `token=` and `Authorization`.
8. Security-boundary changes (egress, auth, SQL) get a short review note in the commit message.
9. Every state change somebody could ask "who did that?" about calls `app.service.audit.record` in the same transaction (add the action to `ACTIONS` with its label, test it in the style of `tests/test_audit_log.py`). Details are small facts (ids, counts, rule ids), never passwords, secrets or text people typed.

## Process
- Small vertical slices; one commit per slice on branch `mvp`; ask before pushing.
- Strings in templates and flash messages go through `_()`; a sentence kept in a constant, a table, an error or a validator is marked with `N_` (`app/messages.py`) where it is written; a new or changed sentence needs its German row (`scripts/translations.py update`, translate, `compile`: a test fails while an offered language is incomplete or the template is stale); English first, de-CH next to it (`LANGUAGES` in `app/config.py` lists what is offered; with two or more the account menu has a Language group, and the language of a page is the account's, else the browser session's, else the browser's: `app/i18n.py`). Quotes and apostrophes in Python strings are straight (`"` `'`; ruff's RUF001 refuses the typographic ones); in template text an apostrophe is `’` and a quotation mark is `"`. A test that looks for a sentence in a page decodes the page's entities first with `html.unescape` (Jinja writes `'` as `&#39;`).
- Invisible and control characters (a byte order mark, a zero-width space, a bidirectional override, a bell) never stand in a file as themselves: write `\N{ZERO WIDTH NO-BREAK SPACE}` or `chr(0xFEFF)` and save files as UTF-8 without BOM. `tests/test_source_characters.py` fails on one in any tracked or new file (file:line:column and its name); ruff's PLE25 flags the ones a Python string can hold. An editor that turns a typed unicode escape into the character is how `CSV_BOM` once became an empty-looking string: after editing, re-scan the files for non-ASCII bytes.
- UI uses the existing design tokens (`assets/tokens.css`, `assets/app.css`); rebuild the CSS after template changes.
- The logo and icons in `app/static/brand/` come from the brand kit and are used as supplied (rules and sizes in its README); every document names them through `components/brand_head.html`.
- Every page of Flask-Security-Too that is switched on is a template of ours (`app/templates/security/`: sign-in and its second step, two-factor setup, password change, re-authentication; the library still does the work and the forms post what it expects); its terse wording for failures and confirmations is replaced by `SECURITY_MSG_*` in `app/config.py`. The one rule for the length of a password is `SECURITY_PASSWORD_LENGTH_MIN` (the same as `MIN_PASSWORD_LENGTH` of the account service). The library's pages that are off here would still be its own markup, styled by the `fs-*` classes.
