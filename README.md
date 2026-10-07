# Web Due Diligence

Technical due diligence from a single pane of glass. Enter a vendor's domain; the tool discovers its hosts from Certificate Transparency logs and reviews each one — DNS, TLS, HTTP security headers, network and location, open ports and CVEs, subdomain takeover, the technologies and CDN or WAF it shows, email security, registration data — judges what it found with a documented set of rules ([docs/rules.md](docs/rules.md): findings with severity, confidence and a link to their evidence), and answers three questions: **Where is the data? Who processes it? How secure is the external posture?**

> **Status:** MVP under construction (branch `mvp`). Plan: [docs/roadmap.md](docs/roadmap.md).

**Responsible use.** Only assess domains you are allowed to assess. The tool sends standard, low-impact requests (DNS, a few TLS handshakes, one HTTP GET) and queries public data sources; it never logs in, scans ports or exploits anything.

## Quick start

```bash
uv sync && npm ci && npm run build        # dependencies and styles
cp .env.example .env                       # then fill in DATABASE_URL (PostgreSQL)
uv run flask --app app db upgrade          # create the schema
uv run flask --app app users create-admin  # first account
uv run flask --app app datasets update     # IP location (about 65 MB, monthly) and exploitation data (about 5 MB, daily)
uv run flask --app app worker              # runs the checks (keep it running)
uv run flask --app app run                 # the web app
```

With Docker (the database, the web app and the worker in containers; details in [docs/deploy.md](docs/deploy.md)):

```bash
cp .env.example .env                                  # set POSTGRES_PASSWORD and the four secrets
docker compose up -d --build
docker compose run --rm cli flask users create-admin  # first account
docker compose run --rm cli flask datasets update     # IP location data (65 MB) and exploitation data (5 MB)
```

Then open <http://localhost:8080>; for anything but a local trial put HTTPS in front (`docker compose --profile proxy up -d`).

More accounts, switching them off, resetting a password or a lost authenticator: `flask users --help` (with Docker: `docker compose run --rm cli flask users --help`); who sees which assessment: [docs/deploy.md](docs/deploy.md#team-accounts).

## Data sources and attribution

IP geolocation: [DB-IP.com](https://db-ip.com) Lite databases (CC BY 4.0), installed offline by `flask datasets update`. Certificate Transparency names come from ctlogs.dev, CertSpotter and crt.sh. Open ports and CVEs come from the Shodan host API when `SHODAN_API_KEY` is set and from the keyless [Shodan InternetDB](https://internetdb.shodan.io) otherwise (**free for non-commercial use only**); `PORTS_PROVIDER=off` disables them. The CVEs are ranked offline with CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue and the EPSS scores of [FIRST](https://www.first.org/epss/), installed by `flask datasets update` (nothing about a scan is sent for that). Subdomain takeover is judged with a list of hosted services and the pages they show for a name nobody has claimed, adapted from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) (CC BY 4.0). Registration data comes from the registry's RDAP service (found through IANA's bootstrap file), HSTS preload status from hstspreload.org and public breaches from [Have I Been Pwned](https://haveibeenpwned.com) (CC BY 4.0); the domain name is sent to them, and `EXTERNAL_DOMAIN_LOOKUPS` switches each off. Everything a scan sends to anybody, and which setting changes it: [docs/deploy.md](docs/deploy.md#what-leaves-your-network) (the page for a new assessment shows it too). More sources and their terms: [docs/checks-catalog.md](docs/checks-catalog.md).

## Development

Commands and conventions: [CLAUDE.md](CLAUDE.md). How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability: [SECURITY.md](SECURITY.md). Documentation index: [docs/README.md](docs/README.md).

## Licence

Apache License 2.0: see [LICENSE](LICENSE). [NOTICE](NOTICE) lists the third-party material and the data attributions.
