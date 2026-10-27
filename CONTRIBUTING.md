# Contributing

Thanks for helping. This is a small tool for security teams. For anything bigger than a fix, open an issue first so
that we agree on the shape before you write code. Found a vulnerability? Please
follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Set up

You need Python 3.11 or newer with [uv](https://docs.astral.sh/uv/), Node 22 or newer (for the
stylesheet) and a PostgreSQL you may create schemas in.

```bash
uv sync && npm ci && npm run build
cp .env.example .env                        # fill in DATABASE_URL and TEST_DATABASE_URL
uv run flask --app app db upgrade
uv run flask --app app users create-admin
uv run flask --app app worker               # one terminal: runs the checks
uv run flask --app app run --debug          # another: the web app
```

The test database name must contain `test`; the test run creates and drops its own schema. If your
role cannot write to `public`, set `DB_SCHEMA` for the development database. The README and
[docs/deploy.md](docs/deploy.md) cover Docker.

## Before you open a pull request

```bash
uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest
```

CI runs the same on Python 3.11 and 3.13 with PostgreSQL 16, `pip-audit` next to it and, on pull
requests, a check that every commit is signed off (see below). Unit tests
never touch the network; a test that needs the real network is marked `@pytest.mark.live` and runs
only with `-m live`.

## The rules that matter

[CLAUDE.md](CLAUDE.md) has the full list (it is also the guide for coding agents). In short:

- **Typed outcomes** (`ok`, `no_data`, `unavailable`, `error`, `skipped`): never show "clean" for
  "not checked". Having no findings is not "clean"; the pages say what the rules could not see.
- **Every fact carries a subject, a source and a time.** A certificate name is not a live host, and
  an address is not a hostname attribution.
- **Everything is bounded**: hosts, bytes, time, concurrency, retries. All traffic towards assessed
  hosts goes through `runner/`.
- **Routes are thin**, logic lives in `app/service/`, templates only present, and everything is
  escaped (no `|safe` on collected data).
- **A new check** is one module in `app/checks/`, one test with fixtures and one row in the
  [catalogue](docs/checks-catalog.md) (section 6 explains how). **A new rule** is one function in
  `app/rules/`, a test in `tests/rules/` fed with the real check's output, and a regenerated
  [docs/rules.md](docs/rules.md) (`uv run python -m app.rules.docs`; a test fails when it is stale).
- **State changes are audited** (`app.service.audit.record`, in the same transaction), and the
  details never hold passwords, secrets or text somebody typed.
- Provider keys come from the environment only. Strings in templates and flash messages go through
  `_()`. After a template change run `npm run build`: the compiled stylesheet is committed.

## Pull requests

- Keep them small and about one thing; say why in the description.
- Change the docs and the `.env.example` together with the code.
- A change to the security boundary (egress, sign-in, SQL, secrets) gets a short review note in
  the description: what could go wrong and why it cannot.
- Dependencies: only what the code imports (`tests/test_dependencies.py` checks it), and only under
  a permissive licence: add one with `uv add`, then its licence to the table in
  `tests/test_licences.py` (Apache-2.0, MIT, BSD, ISC, PSF, MPL-2.0 and public-domain licences are
  accepted; GPL and AGPL are not, and anything else needs a review first). On Windows stop a
  running worker or web server first, or `uv sync` cannot replace the compiled files they have
  loaded.
- A new place the application sends something to (a provider, a download) is listed in
  [docs/deploy.md](docs/deploy.md#what-leaves-your-network) with its setting, and in
  `app/service/disclosure.py`; `tests/test_outbound.py` fails otherwise. The application does not
  phone home (no telemetry, no crash reports, no update or licence checks) and its pages load
  nothing from outside; a pull request cannot change that quietly.

## Sign your commits (DCO)

Every commit of a pull request carries a sign-off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): by signing off you certify
that you wrote the change, or have the right to submit it, under the project's licence.
`git commit -s` adds the line (`Signed-off-by: Your Name <you@example.org>`, from your `user.name`
and `user.email`), and the address must be the one of the commit's author. CI checks every commit
of a pull request, merges and bots aside, and says which ones lack it. To fix commits that exist
already:

```bash
git commit --amend --no-edit -s     # the last commit only
git rebase --signoff main           # every commit of the branch
git push --force-with-lease
```

## Licence of contributions

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), like the rest of the project (section 5 of the licence).
