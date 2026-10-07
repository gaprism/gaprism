# Deploying with Docker Compose

`docker-compose.yml` runs the application next to its own PostgreSQL: **web** (gunicorn), **worker** (the scan queue) and **migrate** (brings the schema up to date before either starts). One image, built from the `Dockerfile`, serves all three. An optional **proxy** (Caddy) puts HTTPS in front.

| Service | What it does | Reaches |
|---|---|---|
| `db` | PostgreSQL 17; data in the volume `pgdata` | nothing: an internal network with no route out, no port on the host |
| `migrate` | `flask db upgrade`, then exits | the database |
| `web` | the application, published on `127.0.0.1:8080` | the database |
| `worker` | the checks of every scan: DNS, TLS, HTTP, discovery, provider lookups | the database and the internet |
| `proxy` (profile `proxy`) | HTTPS and certificates, forwards to `web` | `web` |
| `cli` (profile `tools`) | one-off commands, never started by `up` | the database and the internet |

## Quickstart

Needs Docker Engine with Compose v2. On a machine with only this checkout:

```bash
cp .env.example .env
```

Edit `.env`: set `POSTGRES_PASSWORD` and the four secrets `SECRET_KEY`, `SECURITY_PASSWORD_SALT`, `MFA_ENCRYPTION_KEY` and `AUTH_RATE_LIMIT_KEY`, each to the output of `openssl rand -hex 32` (hex never contains the words the production check rejects). Provider keys (`SHODAN_API_KEY`, …) are optional; leave them empty for keyless access.

```bash
docker compose up -d --build                       # build the image, start database, web and worker
docker compose run --rm cli flask users create-admin    # the first account
docker compose run --rm cli flask datasets update       # IP location data (about 65 MB) and exploitation data (about 5 MB)
```

Then open <http://localhost:8080>. The first sign-in asks the user to enrol an authenticator app (`REQUIRE_MFA`, on by default in production).

**HTTPS.** Production sets the session cookie `Secure`, so signing in works only over HTTPS, with one exception: `http://localhost` (Chrome, Edge and Firefox treat it as secure; Safari does not). Anything else needs the proxy below.

## HTTPS and reverse proxies

**The bundled proxy** (Caddy, certificates by itself):

```bash
# .env:  SITE_ADDRESS=dd.example.org   TRUSTED_PROXY_COUNT=1
docker compose --profile proxy up -d
```

`SITE_ADDRESS` must be a name that points at this machine, with ports 80 and 443 reachable from the internet (Let's Encrypt). With `localhost` Caddy uses its own certificate authority, which browsers do not trust: fine for a trial. Without a public name, uncomment `tls internal` in `deploy/Caddyfile` (and have people trust Caddy's root certificate) or use the proxy you already run.

**Your own proxy** (nginx shown): forward to `127.0.0.1:8080`, pass the original `Host`, and say who the client is:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Whichever proxy it is, set **`TRUSTED_PROXY_COUNT=1`** in `.env` (one proxy in front; more if you chain them). The sign-in limit blocks an address after five failures; behind a proxy the app only knows the clients' addresses from `X-Forwarded-For`, and without the setting everybody shares the proxy's address, so five failures from anyone block everyone for 15 minutes (the log says so once). Set it only when the app cannot be reached except through the proxy: it takes the last entry the proxy appended, so a client that sends the header itself cannot choose its address, but one that reaches the app directly can. Compose publishes `web` on the loopback interface only (`WEB_BIND`), which keeps that true.

## Settings

Everything in `.env.example` works in `.env`; compose adds these:

| Setting | Default | Meaning |
|---|---|---|
| `POSTGRES_PASSWORD` | – (required) | password of the database container, set when its volume is first created |
| `POSTGRES_USER`, `POSTGRES_DB` | `due_diligence` | |
| `WEB_BIND`, `WEB_PORT` | `127.0.0.1`, `8080` | where the web app is published on the host |
| `WEB_WORKERS`, `WEB_THREADS` | `2`, `4` | gunicorn processes and threads per process |
| `SITE_ADDRESS`, `HTTP_PORT`, `HTTPS_PORT` | `localhost`, `80`, `443` | the bundled proxy |
| `TRUSTED_PROXY_COUNT` | `0` | proxies in front of the app, see above |

`DATABASE_URL` in `.env` is for running without Docker; compose builds its own from `POSTGRES_*`.

**Keep these.** `SECURITY_PASSWORD_SALT` and `MFA_ENCRYPTION_KEY` must not change once people have accounts: with another salt no password verifies any more, and with another key no enrolled authenticator can be read. `SECRET_KEY` only signs sessions (a new one signs everybody out) and `AUTH_RATE_LIMIT_KEY` only hides addresses in the limit's counters. Back `.env` up together with the database.

## Operating it

```bash
docker compose ps                         # state and health
docker compose logs -f web worker         # what happens (rotated: 5 files of 10 MB each)
docker compose up -d --build              # upgrade after `git pull`: rebuilds, migrates, restarts
docker compose up -d --scale worker=2     # more workers (each runs WORKER_THREADS checks at once)
docker compose stop                       # stop, keep everything
docker compose down                       # remove the containers, keep the volumes
docker compose down -v                    # remove the volumes as well: THE DATA IS GONE
```

An upgrade runs the migrations first; the web app and the worker start only when they have succeeded. Rebuild with `--pull` now and then to pick up security fixes of the base images.

**Location data** (DB-IP Lite) is published monthly and the **exploitation data** (CISA's Known Exploited Vulnerabilities catalogue and FIRST's EPSS scores, which rank the CVEs a scan reports) changes every day. Without the first the IP check says so and names the command; without the second the CVE findings stay Informational and say that they were not ranked. One command updates all four files and leaves a download that is less than twelve hours old alone, so a daily run from cron keeps both current (`-T` because cron has no terminal):

```cron
0 4 * * *  cd /srv/web-due-diligence && docker compose run --rm -T cli flask datasets update
```

`flask datasets status` shows what is installed, how old it is and where it came from; data older than a week is flagged on the host page and in the findings.

**Backup** the database and the settings together:

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > backup-$(date +%F).dump
cp .env backup-$(date +%F).env          # secrets: store it as carefully as you store them
```

**Restore** into a stack that has no data yet:

```bash
docker compose up -d db
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner' < backup-2026-10-06.dump
docker compose up -d
```

Volumes: `pgdata` (the database), `datasets` (IP location data, can be downloaded again), `caddy_data` (certificates), `caddy_config`.

## Team accounts

There is no sign-up and no password-reset mail: administrators run the accounts from the command line, with `docker compose run --rm cli flask users …` (without Docker: `uv run flask --app app users …`).

| Command | What it does |
|---|---|
| `users create-admin` | the first administrator (asks for the e-mail address and the password); on an existing account it resets the password |
| `users create EMAIL [--admin]` | a team account |
| `users list` | the accounts: role, switched on or off, whether an authenticator is enrolled, last sign-in |
| `users set-password EMAIL` | a new password; the person is signed out everywhere |
| `users deactivate EMAIL` · `users activate EMAIL` | switch an account off (it is signed out with its next request) or on again |
| `users grant-admin EMAIL` · `users revoke-admin EMAIL` | give or take the administrator role |
| `users reset-mfa EMAIL` | forget a lost authenticator; the person sets up a new one at the next sign-in |

Passwords are asked for at a hidden prompt, never taken as arguments (they would show up in the process list and the shell history), and need 12 characters. In a script on Linux or in a container the prompt also reads standard input (`printf '%s\n%s\n' "$PW" "$PW" | docker compose run --rm -T cli flask users create EMAIL`); on Windows run the command in a terminal. The last active administrator cannot be switched off or demoted. Every change goes into the [audit log](#limits-and-the-audit-log), without the password. People change their own password with *Password* in the page header; no mail is sent about it.

**Who sees what.** An assessment is private when it is created: only its owner and the administrators can open it. On the assessment page the owner or an administrator can *Share with the team* (and make it private again). A shared assessment can be opened by every signed-in user, who can scan it, add hosts and decide about its findings, but only the owner and the administrators change who sees it. A domain is shared once: sharing a second assessment of the same domain is refused. When somebody leaves, switch the account off; their private assessments stay, and an administrator can share them.

**Archive and delete.** The owner and the administrators can archive an assessment: it leaves the list (the *Archived* tab has it), cannot be scanned or changed, and can be restored; its reports, exports and history stay available. They can also delete it, which removes it with all its scans, hosts, findings and decisions for good, after typing its domain; take a [backup](#operating-it) first if you may need it again. Neither works while a scan is queued or running, a colleague who only has access to a shared assessment can do neither, and both are written to the [audit log](#limits-and-the-audit-log) (a deleted assessment stays in it by domain).

**Two-factor sign-in** is optional and on by default in production (`REQUIRE_MFA`): a new account sets up an authenticator app at its first sign-in. With `REQUIRE_MFA=false` anybody can still turn it on through *Two-factor* in the page header.

## Limits and the audit log

Three settings bound what the tool does and how long it remembers it (`.env`; `.env.example` lists them):

| Setting | Default | Meaning |
|---|---|---|
| `MAX_HOSTS_PER_RUN` | `200` | hosts one scan reviews; the rest is reported as "over the limit". At most 2000, whatever is set: a larger value stops the start |
| `MAX_SCANS_PER_USER_PER_HOUR` | `20` | scans one person may start in an hour, over all their assessments; `0` switches the limit off (at most 1000) |
| `AUDIT_RETENTION_DAYS` | `730` | how long the audit log keeps an entry; `0` keeps them for ever (at most 3650) |

The scan limit protects the assessed hosts, the data providers and the worker from a script or a stolen session. A person who reaches it is told when the next scan can start, and the refusal is written to the audit log. It is a brake, not a meter: two requests in the same instant can both pass.

**The audit log** answers *who did what, when, to which assessment*. An entry is written in the same database transaction as the change it records, so there is no entry without the change and no change without its entry, and nothing edits an entry afterwards.

| Kind | Entries |
|---|---|
| Sign-in | signed in, signed out, failed sign-in (of an address that has an account), password changed, two-factor setup changed |
| Assessments | created, shared with the team, made private, archived, restored, deleted |
| Hosts | hosts added by hand, a host removed |
| Scans | started, cancelled, refused because of the limit |
| Findings | accepted, marked as a false positive, reopened |
| Exports | report opened, JSON, hosts CSV, findings CSV |
| Accounts | created, new password, switched on or off, administrator role given or taken away, authenticator forgotten |

Each entry has the time (UTC), the person (the e-mail address as it was then), where it came from (the client address, or *command line* for `flask` commands), the assessment, and a few small facts such as the rule of a finding, the number of hosts or the limit that was hit. **It never holds a password, a secret or the reason somebody gave for a decision**; that stays with the decision. A failed sign-in for an address nobody has is not recorded: it may be a password typed into the wrong field, and strangers must not be able to fill the log.

Administrators read it on the **Audit log** page (a link next to *Assessments*, for administrators only; everybody else gets a 404) with filters for the kind, the action, the person, the time and the assessment, and with a command (the same entries, newest first):

```bash
docker compose run --rm cli flask audit list --days 7 --group scan --user @example.org
```

The table is `audit_event` if you prefer SQL. The worker removes entries older than `AUDIT_RETENTION_DAYS` once an hour. Entries outlive the account and the assessment they are about (the links are cleared, the e-mail address and the domain stay as text). Every entry is also written as one line to the `app.audit` logger (`docker compose logs web worker`): ship these lines to a log collector when the record must outlast what a database administrator could change, because the table is only as trustworthy as the access to the database.

## What leaves your network

A scan is not silent. This is everything it sends to somebody else; the page for a new assessment shows the same list for your configuration, and `tests/test_disclosure.py` keeps this table and that list in step. Every recipient also sees the address this server connects from.

| Recipient | What it receives | When | Setting |
|---|---|---|---|
| Certificate Transparency sources: `api.ctlogs.dev`, `api.certspotter.com`, `crt.sh` | the domain name (and your `CTLOGS_API_KEY` or `CERTSPOTTER_TOKEN`, if you set one, as a request header) | discovery, at the start of every scan | `CT_SOURCES` (at least one; a scan cannot find its hosts without) |
| DNS resolvers: `1.1.1.1` and `8.8.8.8` by default | every name that is looked up: the domain, its hosts, and the mail and policy names derived from it (`_dmarc.`, `_mta-sts.`, `_smtp._tls.`) | the DNS, e-mail and domain checks | `EGRESS_DNS_RESOLVERS` (your own resolvers; `system` uses the operating system's) |
| The assessed domain's own servers | TLS handshakes and HTTP requests (the home page, `security.txt`, the MTA-STS policy) with the User-Agent `WebDueDiligence/0.1 (+https://github.com/stalpers/web_due_diligence)`: **the owner can see the scan in their logs** | per host | `USER_AGENT`, `BLOCKED_DOMAINS` (domains that may not be assessed) |
| Shodan InternetDB (`internetdb.shodan.io`, keyless), or the Shodan host API (`api.shodan.io`) when `SHODAN_API_KEY` is set | the public IP addresses of the hosts, never their names (the Shodan key travels in the URL; logs redact it) | per address, cached for `PORTS_CACHE_HOURS` | `PORTS_PROVIDER` (`off` sends nothing) |
| Security DNS resolvers: Quad9 (`9.9.9.9`) and Cloudflare's malware-blocking resolver (`1.1.1.2`) by default | every host name of the assessment, as a plain (unencrypted) DNS question like the DNS check's, so each of them learns the names of the hosts | per host (at most 20 questions per second to each resolver) | `REPUTATION_RESOLVERS` (`none` switches it off) |
| The registry's RDAP service, found through IANA's bootstrap file (`data.iana.org`) | the domain name | once per scan | `EXTERNAL_DOMAIN_LOOKUPS` (`rdap`) |
| `hstspreload.org` | the domain name | once per scan, cached 24 hours | `EXTERNAL_DOMAIN_LOOKUPS` (`hsts_preload`) |
| Have I Been Pwned (`haveibeenpwned.com`) | the domain name | once per scan | `EXTERNAL_DOMAIN_LOOKUPS` (`hibp`) |
| Mozilla's HTTP Observatory (`observatory-api.mdn.mozilla.net`), **off unless you add it** | the domain name; Mozilla's scanner then requests the home page and a few well-known files from the domain's own servers, which see Mozilla, and the scan and its grade are public on MDN and cannot be hidden | once per scan (the domain, or `www.` when the domain itself has no site), cached 24 hours | `EXTERNAL_DOMAIN_LOOKUPS` (add `observatory`) |

Besides the scan, `flask datasets update` downloads public files: the IP location databases from `download.db-ip.com` (with a jsDelivr mirror, `cdn.jsdelivr.net`, as a fallback), the Known Exploited Vulnerabilities catalogue from `www.cisa.gov` and the EPSS scores from `epss.empiricalsecurity.com`, where FIRST publishes them. Nothing about an assessment is sent: the CVEs a scan reports are looked up in the files on your own disk, so who runs which software never leaves your network.

With `EXTERNAL_DOMAIN_LOOKUPS=none`, `REPUTATION_RESOLVERS=none` and `PORTS_PROVIDER=off`, the only outsiders who learn the domain are the certificate-transparency sources and the DNS resolvers, and the assessed servers see the checks. The optional lookups are on by default because their facts (expiry and locks, HSTS preload, breach history, whether security resolvers block a host) are part of the answer; switch them off when the name of the assessed domain must not reach anybody else. A per-assessment switch for that is on the roadmap's backlog. The Mozilla HTTP Observatory is the exception: it makes a third party scan the domain and publishes the result, so it is off until you add `observatory` to `EXTERNAL_DOMAIN_LOOKUPS`. The host pages also link to the SSL Labs server test and to the Observatory; those links send nothing from here, and what a click starts is the visitor's own use of their website (SSL Labs' terms allow its API only for sites whose owners gave permission, which is why it is not called from here). The security resolvers are the only ones of these that learn the names of the *hosts* too; a network that does not let DNS questions through to them makes the check fail (after a few unanswered questions it stops asking for half a minute, so a scan is not held up), and the host pages say so.

## Security notes

- **Containers.** The application runs as an unprivileged user in a read-only container with no capabilities, `no-new-privileges`, memory and process limits and rotated logs. The only writable place is the `datasets` volume, and only the `cli` service mounts it writable. There is no Docker socket anywhere. The database sits on an internal network and publishes nothing.
- **The worker connects to hosts that people type in.** The application refuses to connect to private, loopback and link-local addresses and pins the address it resolved (`runner/`); that gate is in the code, and it is the only thing between the worker and the networks the Docker host can reach. If those include internal networks, add a rule of your own as a second layer: run the stack on a host or VLAN that cannot reach them, or filter the containers' egress. Keep `.env` out of version control and readable by its owner only; anyone in the `docker` group can read the settings of a container (`docker inspect`), so treat that group like root.
- **IPv6.** Docker does not give containers IPv6 by default; a host reachable only over IPv6 then shows failed checks (never a clean result). Enable IPv6 for the Docker network if you need those.
- **No mail, no registration.** Accounts are created on the command line ([Team accounts](#team-accounts)); there is no sign-up, no password-reset mail and no "your password was changed" notice (the change is in the [audit log](#limits-and-the-audit-log) instead).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `set POSTGRES_PASSWORD in .env` from any compose command | `.env` is missing or `POSTGRES_PASSWORD` is empty |
| `docker compose logs migrate` says `SECRET_KEY must be set in production…` | one of the four secrets is empty, too short or contains a rejected word (use `openssl rand -hex 32`) |
| The database rejects the password after you changed it in `.env` | the password is set when the volume is created; change it in the database (`ALTER USER`) or recreate the volume |
| Signing in does nothing or loops | plain HTTP on an address other than `localhost`: the `Secure` cookie is dropped; use HTTPS |
| Everyone is told "Too many attempts" | `TRUSTED_PROXY_COUNT` is 0 behind a proxy: all clients count as one address |
| Scans stay queued | the worker is not running (`docker compose ps`, `docker compose logs worker`) |
| "You have started the most scans allowed in an hour" | `MAX_SCANS_PER_USER_PER_HOUR`: the message says when the next scan can start; raise the limit or set it to `0` |
| The worker logs `relation "audit_event" does not exist` (or another missing table) | the database is behind the code: run `flask db upgrade` (`docker compose up -d --build` does it) |
| Somebody forgot the password or lost the phone | `users set-password EMAIL`, `users reset-mfa EMAIL` |
| IP location says "unavailable" | run `docker compose run --rm cli flask datasets update` |
