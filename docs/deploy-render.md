# A shared demo on Render

`render.yaml` is a [Render Blueprint](https://render.com/docs/blueprint-spec) that runs the application as **one free web service** next to a **free PostgreSQL database at Neon**, so that colleagues can try the tool in a browser without installing anything. It is for demonstrations. The free tier sleeps, is slow and has no real backups; for real assessments run [docker compose](deploy.md) on a machine of your own.

| Part | How it runs |
|---|---|
| Web app, scan worker, migrations | One container of the same image as in compose. `deploy/render-start.sh` brings the schema up to date, starts the worker (and starts it again if it stops) and then the web server: the free tier has no background worker and no pre-deploy command |
| Database | Neon, in Frankfurt, created by you. Its address is the only thing you paste into Render |
| IP location, exploitation and blocklist data | Installed into the image during the build (`BAKE_DATASETS=1`; 80 MB to download, 160 MB in the image): the disk of a free service is gone after every restart |
| Deploys | By hand: a push does not reach the demo (`autoDeployTrigger: "off"`), apart from a change of `render.yaml` itself (see *Later deploys*) |
| Settings | Limits for a small shared demo: 30 hosts per scan, 10 scans per hour and person, two checks at a time, two-step sign-in on, `render.com` and `onrender.com` not assessable. The sources whose terms need your decision (Shodan InternetDB, URLhaus) are off, and there are no provider keys. Everything else is as in `.env.example` |

## What to expect

| Limit (October 2026; check the providers' pages) | What it means for the demo |
|---|---|
| Render stops a free web service after 15 minutes without a request | The first request after a pause takes one to two minutes: Render starts the container (about a minute), then the application starts on 0.1 CPU. A scan that is running at that moment is not lost: its checks are picked up ten minutes later, when somebody wakes the service |
| 0.1 CPU and 512 MB | A scan of 30 hosts takes minutes, not seconds. The web server and the worker together use about 165 MB when idle, which leaves room for a scan; two people scanning at once is slow, and a memory limit is possible (see *Troubleshooting*) |
| 750 free instance hours a month for the whole Render workspace | One service that is awake all month uses about 720. When the hours are used up, Render suspends free web services until the next month |
| Neon free plan, per project: 1 GB of storage, 100 compute-hours a month (a small compute uses a quarter of one per hour awake: about 400 hours) and 5 GB of network transfer; the compute stops after 5 minutes without a query | The worker asks the database for work every few seconds, so the database is awake as long as the service is. That is plenty for a few people. Storage fills with scans: archive and delete old assessments, and watch the usage in the Neon console. When the compute-hours are used up Neon suspends the compute until the next month; when the storage is full, writes fail |
| No shell, no disk, no backups beyond Neon's six-hour restore window | Accounts are created from your own machine (below). If the database is deleted, the demo starts empty |
| Free builds count against the workspace's build minutes | A build takes several minutes. Without a payment method Render stops new builds when the minutes are used up; running services stay up |
| Render may suspend a free service with an unusually high volume of outbound traffic | Keep scans small |

**What your peers must know.** Everything they type and every result is stored at Neon and handled by Render, both in Frankfurt, and you can read all of it. The accounts hold their e-mail addresses and the [audit log](deploy.md#limits-and-the-audit-log) their actions. Scans start from Render's servers and send requests to the assessed domain's servers, whose owners can see them (the User-Agent names the tool). Render's [penetration testing policy](https://render.com/docs/penetration-testing) lets customers test their own services; testing another customer's infrastructure needs that customer's explicit consent, and denial-of-service tests are banned (see also its [acceptable use policy](https://render.com/acceptable-use)). The checks here read public information and send ordinary requests to each host (DNS questions, TLS handshakes, a few page requests), but a company's website can be hosted at Render under its own name, and the Blueprint refuses only Render's own names: tell peers to assess only domains they are entitled to look at, and nothing confidential. Set `USER_AGENT` to a page that says who runs the demo if you want the owners of scanned sites to know whom to ask.

## Before you start

- **A Render account.** A free workspace is enough. Render may ask for a payment method.
- **Access for Render to the repository.** Render's GitHub app needs access to `stalpers/web_due_diligence` (private): on GitHub's authorisation screen choose that repository only. The Blueprint is read from the branch you choose (`mvp`) and deploys that branch.
- **A Neon account.**
- **This repository on your machine**, with `uv sync` done: the accounts are created from there.

## 1. The database at Neon

1. Create a project in the region **AWS Europe (Frankfurt), `aws-eu-central-1`**, next to the Render service.
2. Open *Connect* and copy the **direct** connection string: *Connection pooling* off, a host like `ep-….eu-central-1.aws.neon.tech` without `-pooler`, ending in `?sslmode=require…`. The application keeps its own connection pool, and migrations should not go through a pooler.
3. Keep the string to yourself: it is the password of the database, and anyone who has it can read everything (the free plan cannot restrict the addresses that may connect). If it leaks, reset the password in Neon and update `DATABASE_URL` at Render.

The application accepts the `postgresql://…` form as Neon gives it (it adds the driver itself).

## 2. The Blueprint

1. In the Render dashboard: **New > Blueprint**, **Connect** the repository, give the Blueprint a name, select the branch `mvp`.
2. Render lists what it will create: the service `web-due-diligence-demo` (free). It asks for `DATABASE_URL`: paste the Neon string. The four secrets are generated by Render.
3. **Deploy Blueprint**. The first build takes several minutes: it builds the stylesheet, installs the dependencies and downloads the data. The first start brings the empty database up to date.
4. When the deploy is *Live*, open the address shown for the service (`https://web-due-diligence-demo.onrender.com`, with a suffix if the name was taken) and `/healthz`, which answers `{"env":"production","status":"healthy"}` without touching the database.
5. On the Blueprint's *Settings* page set **Auto Sync** to *No*. Otherwise every push to `mvp` that changes `render.yaml` is synced and redeploys the service with the latest commit of the branch, which is what `autoDeployTrigger: "off"` is meant to prevent.

**Later deploys:** *Manual Deploy > Deploy latest commit* on the service. The data is part of the image, so it is as old as the last build that was not served from Render's layer cache: any change of the code rebuilds it, and for the same commit use *Clear build cache & deploy*. The host pages flag location and exploitation data that is older than a week. A change to `render.yaml` (a limit, the plan) reaches the service with *Manual Sync* on the Blueprint's page; Render keeps the values of the variables it generated and of the ones you pasted, and settings you changed by hand in the dashboard are overwritten if they conflict with the file.

## 3. Accounts

There is no sign-up and, on the free tier, no shell. Create the accounts from your machine against the Neon database, in the checkout, **once the service is *Live***: the tables are created when it starts for the first time. The password is stored together with the service's `SECURITY_PASSWORD_SALT`, so use the service's own value (*Environment* tab of the service; do not change it afterwards, it would lock everybody out). PowerShell:

```powershell
$env:FLASK_SKIP_DOTENV = "1"     # do not read .env: it names the schema of the development database
$env:DATABASE_URL = Read-Host "Neon connection string"
$env:SECURITY_PASSWORD_SALT = Read-Host "SECURITY_PASSWORD_SALT of the Render service"
uv run flask --app app users create-admin
uv run flask --app app users create user@example.org
Remove-Item Env:FLASK_SKIP_DOTENV, Env:DATABASE_URL, Env:SECURITY_PASSWORD_SALT
```

Each command asks for the password at a hidden prompt (12 characters at least). The other commands, `users list`, `set-password`, `deactivate`, `reset-mfa`, are the ones in [Team accounts](deploy.md#team-accounts); run them the same way. The first sign-in asks for an authenticator app (`REQUIRE_MFA`). Send each person the address and the e-mail they sign in with, and the initial password by another route.

**Where is the salt?** You do not set it: Render generated it when the Blueprint was deployed. In the dashboard open the service, click **Environment** in the left pane and look under **Environment Variables** for `SECURITY_PASSWORD_SALT`; copy its value into the prompt of the recipe. If the variable is missing (the service was not created from the Blueprint) or its value cannot be read, and nobody has an account yet, set your own: generate one with `uv run python -c "import secrets; print(secrets.token_hex(32))"`, add or edit the variable on that page, choose **Save and deploy**, and use the same value in the recipe. Once accounts exist, never change it.

**Why `FLASK_SKIP_DOTENV`.** `flask` reads the `.env` of the checkout, and its `DB_SCHEMA` points every command at the schema of your development database, which does not exist at Neon (the error is `relation "role" does not exist`). Blanking the variable does not help in PowerShell: `$env:DB_SCHEMA = ""` deletes it, and `.env` wins. If the tables are missing because the service has not started (or failed to), `uv run flask --app app db upgrade` with the same variables creates them; once they exist it does nothing.

## 4. Check once: the client address

Behind Render's proxy the application learns the visitor's address from `X-Forwarded-For`, and the sign-in limit counts failures per address. The Blueprint sets `TRUSTED_PROXY_COUNT=1`: the application takes the last entry of the header, the one the nearest proxy appended, so a client that sends the header itself cannot choose its address. Render does not document how many entries its proxies add, so check once. Sign in (after you have set up the authenticator), open the **Audit log** (administrators) and read the *From* column of your own *Signed in* entry:

- **Your public address**: done.
- **Another address, the same for everybody** (Render's or its CDN's): set `TRUSTED_PROXY_COUNT` to `2`, in `render.yaml` (a later sync would put the old value back) and in the service's *Environment* tab, deploy, sign in again and look again. Use the lowest number that shows your own address: a number higher than the proxies that really append makes the address one a visitor can choose.
- Everyone gets "Too many attempts" after a few failed sign-ins: the same cause, the same remedy.

## An invitation to paste

> **Web Due Diligence, test environment**
>
> Address: https://… (the first request after a pause can take two minutes)
> Sign in with your e-mail address; I send the initial password separately. At your first sign-in you set up an authenticator app (two-step sign-in is mandatory).
>
> This is a demonstration on free infrastructure: it is slow, it sleeps and it can lose its data. I can read everything in it, so enter nothing confidential, and assess only domains you may look at. Scans start from Render's servers and the assessed site can see them. Please keep scans small: at most 30 hosts, and ten scans an hour per person.
>
> What it does: enter a domain, it finds the hosts through Certificate Transparency and runs technical checks on each (DNS, TLS, web headers, e-mail security, where the servers are, who runs them) and answers where the data is, who processes it and how secure the external posture looks. Feedback is welcome.

## Pausing and removing it

*Settings > Suspend Service* stops the service (the database stays); *Delete Service* removes it, and deleting the Neon project removes the data and every account. Neither can be undone.

## Troubleshooting

The log of the service (the *Logs* tab) holds the output of the start script, the web server and the worker, and the [audit](deploy.md#limits-and-the-audit-log) lines.

| Symptom | Cause |
|---|---|
| The build fails in `flask datasets update` | One of the downloads failed (the log names it). Deploy again |
| The deploy ends with `the schema is not up to date after 5 attempts` | `DATABASE_URL` is wrong, or the Neon project is suspended (storage or compute quota). The line above it in the log says what the database answered |
| Creating an account fails with `relation "role" does not exist` | The command read `DB_SCHEMA` from your `.env` (set `FLASK_SKIP_DOTENV` as in *Accounts*), or the database has no tables yet because the service has not started: wait until it is *Live*, or run `db upgrade` as described there |
| `SECRET_KEY cannot contain weak/default patterns` | About one generated key in 800 contains `dev`, `test` or the like. Replace `SECRET_KEY` with any other long random value |
| "Bad gateway" or a waiting page on the first request | The service is waking up; wait two minutes |
| Nobody can sign in after a deploy | `SECURITY_PASSWORD_SALT` or `MFA_ENCRYPTION_KEY` changed. Put the old value back; with a new one the accounts must be created again |
| The service restarts during a scan and Render's events say it ran out of memory | Set `WORKER_THREADS` to `1`, or move to a paid instance type (`plan: starter`); change it in `render.yaml` and sync, so that the file and the service agree |
| A scan stays *running* after the service was asleep | Wait ten minutes: the lock on its checks expires and the worker takes them again |
| Ports and CVEs say "Switched off" | `PORTS_PROVIDER=auto` without a Shodan key is off on purpose: [Off until you decide](deploy.md#what-leaves-your-network) |
