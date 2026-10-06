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
docker compose run --rm cli flask datasets update       # IP location data, about 65 MB
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

**Location data** (DB-IP Lite) is published monthly. Without it the IP check says so and names the command; to keep it current, run the update monthly, for example from cron (`-T` because cron has no terminal):

```cron
0 4 2 * *  cd /srv/web-due-diligence && docker compose run --rm -T cli flask datasets update
```

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

## Security notes

- **Containers.** The application runs as an unprivileged user in a read-only container with no capabilities, `no-new-privileges`, memory and process limits and rotated logs. The only writable place is the `datasets` volume, and only the `cli` service mounts it writable. There is no Docker socket anywhere. The database sits on an internal network and publishes nothing.
- **The worker connects to hosts that people type in.** The application refuses to connect to private, loopback and link-local addresses and pins the address it resolved (`runner/`); that gate is in the code, and it is the only thing between the worker and the networks the Docker host can reach. If those include internal networks, add a rule of your own as a second layer: run the stack on a host or VLAN that cannot reach them, or filter the containers' egress. Keep `.env` out of version control and readable by its owner only; anyone in the `docker` group can read the settings of a container (`docker inspect`), so treat that group like root.
- **IPv6.** Docker does not give containers IPv6 by default; a host reachable only over IPv6 then shows failed checks (never a clean result). Enable IPv6 for the Docker network if you need those.
- **No mail, no registration.** Accounts are created on the command line (`flask users create-admin`, which also resets a password); there is no sign-up and no password-reset mail.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `set POSTGRES_PASSWORD in .env` from any compose command | `.env` is missing or `POSTGRES_PASSWORD` is empty |
| `docker compose logs migrate` says `SECRET_KEY must be set in production…` | one of the four secrets is empty, too short or contains a rejected word (use `openssl rand -hex 32`) |
| The database rejects the password after you changed it in `.env` | the password is set when the volume is created; change it in the database (`ALTER USER`) or recreate the volume |
| Signing in does nothing or loops | plain HTTP on an address other than `localhost`: the `Secure` cookie is dropped; use HTTPS |
| Everyone is told "Too many attempts" | `TRUSTED_PROXY_COUNT` is 0 behind a proxy: all clients count as one address |
| Scans stay queued | the worker is not running (`docker compose ps`, `docker compose logs worker`) |
| IP location says "unavailable" | run `docker compose run --rm cli flask datasets update` |
