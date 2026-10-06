# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Use GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose **Report a
vulnerability** (<https://github.com/stalpers/web_due_diligence/security/advisories/new>). Say what
you found, how to reproduce it and which version or commit you looked at.

We acknowledge a report as soon as we can, work on a fix with you and credit you in the release notes
unless you prefer not to be named. Please give us a reasonable time to fix a problem before you
disclose it.

## What counts

The most serious class is anything that makes the worker connect where it should not. The
application connects to hosts that people type in, and `runner/` is the gate: private, loopback and
link-local addresses are refused, the resolved address is pinned, and redirects, sizes and times are
capped. Other examples:

- getting around sign-in, the team rules or the administrator checks (assessments of other people,
  exports, sharing, the audit log);
- cross-site request forgery, injection, or output that is not escaped;
- secrets or provider keys reaching a log, an export, the audit log or an image;
- a weakness in the Docker kit (`Dockerfile`, `docker-compose.yml`, `deploy/`).

Out of scope: what the tool reports about the domains it assesses, the third-party services it
queries, and a deployment that ignores [docs/deploy.md](docs/deploy.md) (plain HTTP on the internet,
for example).

## Supported versions

There are no releases yet. Only the default branch (`mvp`) is maintained.

## For operators

[docs/deploy.md](docs/deploy.md) lists what is hardened and what is left to you: the containers,
proxy trust (`TRUSTED_PROXY_COUNT`), the worker's network access, the secrets that must never change
once people have accounts, and what the audit log can and cannot prove. Keep the dependencies
current: CI runs `pip-audit`, and `uv lock --upgrade` refreshes the lock.
