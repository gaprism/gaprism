"""Flask CLI commands: thin entry points that call services."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import click
import httpx
from flask import Flask, current_app
from sqlalchemy import select

from app.extensions import db
from app.models import Assessment
from app.models.base import utc_now
from app.rules import RULES
from app.service import audit as audit_service
from app.service import blocklists as blocklists_service
from app.service import exploits as exploits_service
from app.service import findings as findings_service
from app.service import geo as geo_service
from app.service import invitations as invitation_service
from app.service import scans as scan_service
from app.service import users as user_service
from app.service import worker as worker_service


def _megabytes(size: int | None) -> str:
    return f"{(size or 0) / (1024 * 1024):.1f} MB"


def _attribution(blocklists: list[str]) -> str:
    credits = [
        f"{geo_service.ATTRIBUTION} ({geo_service.LICENCE}), {geo_service.ATTRIBUTION_URL}",
        exploits_service.KEV_ATTRIBUTION,
        exploits_service.EPSS_ATTRIBUTION,
        *blocklists_service.attributions(blocklists),
    ]
    return "Data: " + "; ".join(credits)


def _dataset_date(kind: str) -> str:
    """What the date of a dataset is called: a database is built, a release is as of."""
    return "build" if kind in ("city", "asn") else "as of"


# Blocklists that are off by default because their terms need the operator's decision.
_TERMS_HINT = {
    "urlhaus": (
        " - not on by default: free under abuse.ch's fair use principles, use by companies may "
        "need a paid licence; add it to BLOCKLIST_PROVIDERS once you have read its terms"
    ),
}


def register_cli_commands(app: Flask) -> None:
    """Register custom Click CLI commands with the Flask application."""

    @app.cli.group(name="datasets")
    def datasets_group() -> None:
        """IP location (DB-IP Lite), exploitation data (CISA KEV, EPSS) and blocklists (URLhaus,
        Feodo Tracker, Phishing.Database), installed offline."""

    @datasets_group.command(name="status")
    def datasets_status() -> None:
        """Show which databases are installed, how old they are and where they came from."""
        directory = Path(app.config["DATASETS_DIR"])
        enabled = list(app.config["BLOCKLIST_PROVIDERS"])
        click.echo(f"Directory: {directory}")
        missing = False
        for item in [
            *geo_service.dataset_status(directory),
            *exploits_service.status(directory),
            *blocklists_service.status(directory, only=enabled),
        ]:
            if not item.present:
                missing = True
                click.echo(f"  {item.kind}: {item.problem}")
                continue
            age = f"{item.age_days} days old" + (
                " - STALE, run `flask datasets update`" if item.stale else ""
            )
            click.echo(f"  {item.kind}: {_dataset_date(item.kind)} {item.build} ({age})")
            click.echo(f"      source: {item.source or 'unknown'}")
            click.echo(f"      sha256: {item.sha256 or 'unknown'}")
        for key in blocklists_service.PROVIDERS:
            if key not in enabled:
                click.echo(f"  {key}: switched off (BLOCKLIST_PROVIDERS){_TERMS_HINT.get(key, '')}")
        if missing:
            click.echo("Run `flask datasets update` to install the missing data.")
        click.echo(_attribution(enabled))

    @datasets_group.command(name="update")
    @click.option(
        "--force", is_flag=True, help="Download again even if the installed data is recent."
    )
    def datasets_update(force: bool) -> None:
        """Download and install the DB-IP Lite city and ASN databases (about 65 MB), the CISA KEV
        and EPSS exploitation data (about 5 MB; both change daily) and the blocklists chosen by
        BLOCKLIST_PROVIDERS (about 11 MB; they change every few hours, so run this regularly)."""
        directory = Path(app.config["DATASETS_DIR"])
        enabled = list(app.config["BLOCKLIST_PROVIDERS"])
        click.echo(f"Installing into {directory} (this can take a minute)...")
        with httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0, read=120.0),
            headers={"User-Agent": str(app.config["USER_AGENT"])},
            trust_env=False,
        ) as client:
            reports = [
                *geo_service.update_datasets(directory, client, force=force),
                *exploits_service.update(directory, client, force=force),
                *blocklists_service.update(directory, client, force=force, only=enabled),
            ]
        failed = False
        for report in reports:
            if report.status == "failed":
                failed = True
                click.echo(f"  {report.kind}: FAILED - {report.detail}")
            elif report.status == "current":
                click.echo(f"  {report.kind}: already current ({report.detail})")
            else:
                click.echo(
                    f"  {report.kind}: updated, {report.detail}, {_megabytes(report.size)}, "
                    f"sha256 {(report.sha256 or '')[:16]}..."
                )
        click.echo(_attribution(enabled))
        if failed:
            raise click.ClickException("At least one database could not be installed.")

    @app.cli.group(name="findings")
    def findings_group() -> None:
        """Findings: the rules applied to what the checks collected."""

    @findings_group.command(name="rules")
    def findings_rules() -> None:
        """List the rules (the full catalogue is docs/rules.md)."""
        for rule in sorted(RULES.values(), key=lambda r: (r.scope, r.id)):
            severities = "/".join(rule.severities)
            click.echo(f"{rule.id:28} {rule.scope:7} v{rule.version}  {severities}")
        click.echo(f"{len(RULES)} rules, set {findings_service.ruleset_digest()}")

    @findings_group.command(name="evaluate")
    @click.option("--domain", default=None, help="Only the latest scan of this assessment.")
    def findings_evaluate(domain: str | None) -> None:
        """Run the rules again over the latest finished scan of every assessment.

        A scan evaluates its own findings when it finishes; use this after the rules changed, or
        for scans that finished before findings existed. Decisions about findings are kept.
        """
        session = db.session()
        query = select(Assessment)
        if domain:
            query = query.where(Assessment.domain == domain.strip().lower())
        done = 0
        for assessment in session.scalars(query):
            scan = scan_service.get_latest_scan(session, assessment.id)
            if scan is None or not scan.is_terminal or scan.status == "cancelled":
                continue
            summary = findings_service.evaluate_scan(session, scan, app.config)
            session.commit()
            done += 1
            counts = ", ".join(f"{n} {name}" for name, n in summary.by_severity.items())
            click.echo(f"{assessment.domain}: {summary.total} findings ({counts or 'none'})")
            if summary.errors:
                click.echo(f"  rules that failed: {', '.join(summary.errors)}")
        if not done:
            click.echo("No finished scan to evaluate.")

    @app.cli.group(name="users")
    def users_group() -> None:
        """Team account administration."""

    @users_group.command(name="create-admin")
    @click.option("--email", prompt="Admin e-mail", help="E-mail address of the administrator.")
    def create_admin(email: str) -> None:
        """Create an administrator, or reset the password of an existing account.

        The password is read from a hidden prompt on purpose: a command-line argument
        would be visible in the process list and the shell history.
        """
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True, type=str)
        try:
            user = user_service.create_admin(db.session(), email, password)
        except user_service.UserAdminError as exc:
            raise click.ClickException(str(exc)) from exc
        db.session.commit()
        click.echo(f"Administrator '{user.email}' is ready.")

    def _new_password() -> str:
        """Ask for a password the way create-admin does: hidden, twice, never as an argument."""
        return click.prompt("Password", hide_input=True, confirmation_prompt=True, type=str)

    def _run(action: Callable[[], str]) -> None:
        """Carry out an account change, commit it, and say what happened; errors are messages."""
        try:
            message = action()
        except user_service.UserAdminError as exc:
            db.session.rollback()
            raise click.ClickException(str(exc)) from exc
        db.session.commit()
        click.echo(message)

    @users_group.command(name="list")
    def users_list() -> None:
        """List the accounts: administrators first."""
        rows = user_service.list_users(db.session())
        if not rows:
            click.echo(
                "There are no accounts yet. Create the first with `flask users create-admin`."
            )
            return
        width = max(len(row.email) for row in rows)
        click.echo(f"{'E-mail':{width}}  {'Role':6}  {'State':8}  {'MFA':3}  Last sign-in")
        for row in rows:
            seen = row.last_login.strftime("%Y-%m-%d %H:%M UTC") if row.last_login else "never"
            state = "off" if not row.active else "invited" if row.invited else "active"
            click.echo(
                f"{row.email:{width}}  {'admin' if row.admin else 'member':6}  "
                f"{state:8}  {'yes' if row.mfa else 'no':3}  {seen}"
            )

    @users_group.command(name="create")
    @click.argument("email")
    @click.option("--admin", is_flag=True, help="Make the account an administrator.")
    def users_create(email: str, admin: bool) -> None:
        """Create a team account. The password is asked for, never given as an argument."""

        def act() -> str:
            clean = user_service.normalise_email(
                email
            )  # a typo is told before the password is asked
            user = user_service.create_user(db.session(), clean, _new_password(), admin=admin)
            return f"Account '{user.email}' created{' as an administrator' if admin else ''}."

        _run(act)

    @users_group.command(name="set-password")
    @click.argument("email")
    def users_set_password(email: str) -> None:
        """Give an account a new password; whoever is signed in with it is signed out."""

        def act() -> str:
            user_service.find_user(db.session(), email)  # no such account: say so first
            user = user_service.set_password(db.session(), email, _new_password())
            return f"New password set for '{user.email}'. Their sessions have ended."

        _run(act)

    @users_group.command(name="deactivate")
    @click.argument("email")
    def users_deactivate(email: str) -> None:
        """Switch an account off: it cannot sign in and its session ends with the next request."""

        def act() -> str:
            if not user_service.set_active(db.session(), email, False):
                return f"'{email}' is switched off already."
            return (
                f"'{email}' is switched off. Their assessments stay; administrators can share them."
            )

        _run(act)

    @users_group.command(name="activate")
    @click.argument("email")
    def users_activate(email: str) -> None:
        """Switch an account on again."""

        def act() -> str:
            if not user_service.set_active(db.session(), email, True):
                return f"'{email}' is active already."
            return f"'{email}' is active again."

        _run(act)

    @users_group.command(name="grant-admin")
    @click.argument("email")
    def users_grant_admin(email: str) -> None:
        """Make an account an administrator: it sees every assessment and can share any."""

        def act() -> str:
            changed = user_service.set_admin(db.session(), email, True)
            return f"'{email}' is an administrator." if changed else f"'{email}' is one already."

        _run(act)

    @users_group.command(name="revoke-admin")
    @click.argument("email")
    def users_revoke_admin(email: str) -> None:
        """Take the administrator role from an account (never from the last active one)."""

        def act() -> str:
            changed = user_service.set_admin(db.session(), email, False)
            return (
                f"'{email}' is not an administrator any more."
                if changed
                else f"'{email}' is not an administrator."
            )

        _run(act)

    @users_group.command(name="reset-mfa")
    @click.argument("email")
    def users_reset_mfa(email: str) -> None:
        """Forget the authenticator of an account (a lost phone): it enrols a new one when MFA is
        required, and can do so by itself when it is not."""

        def act() -> str:
            had = user_service.reset_mfa(db.session(), email)
            return (
                f"The authenticator of '{email}' is forgotten."
                if had
                else f"'{email}' had no authenticator."
            )

        _run(act)

    def _base_url(value: str) -> str:
        """The address of the site as given, without a closing slash; empty when not given."""
        value = value.strip().rstrip("/")
        if value and not value.startswith(("https://", "http://")):
            raise click.ClickException("The base URL must start with https:// or http://.")
        return value

    def _link_lines(link: invitation_service.IssuedLink, base_url: str) -> list[str]:
        """How a new link is shown, once: when it stops working, and the link on its own line."""
        lines = [
            f"The link is valid until {link.expires_at:%Y-%m-%d %H:%M} UTC and is shown only "
            "now: pass it on through your own channel (Gaprism sends no mail)."
        ]
        if not base_url:
            lines.append(
                "Put the address of your site in front of this path, or give --base-url next time:"
            )
        lines.append(base_url + invitation_service.link_path(link.token))
        return lines

    base_url_option = click.option(
        "--base-url",
        default="",
        help="The address of the site, starting with https://, to print the whole link.",
    )

    @users_group.command(name="invite")
    @click.argument("email")
    @click.option("--admin", is_flag=True, help="Make the account an administrator.")
    @base_url_option
    def users_invite(email: str, admin: bool, base_url: str) -> None:
        """Make an account and print the one-time link where its person sets a password.

        Nobody else ever knows the password, and Gaprism sends no mail: pass the link on yourself.
        """
        prefix = _base_url(base_url)

        def act() -> str:
            user, link = invitation_service.invite_user(
                db.session(),
                email,
                admin=admin,
                hours=int(current_app.config["INVITATION_HOURS"]),
            )
            role = "an administrator" if admin else "a member"
            return "\n".join([f"Invited '{user.email}' as {role}.", *_link_lines(link, prefix)])

        _run(act)

    @users_group.command(name="reset-link")
    @click.argument("email")
    @click.option(
        "--authenticator",
        is_flag=True,
        help="Also forget the authenticator when the link is used (a lost phone).",
    )
    @base_url_option
    def users_reset_link(email: str, authenticator: bool, base_url: str) -> None:
        """Print a one-time link where an existing account sets a new password.

        An account that has not accepted its invitation yet gets a new invitation link instead.
        """
        prefix = _base_url(base_url)

        def act() -> str:
            user, link = invitation_service.new_link(
                db.session(),
                email,
                authenticator=authenticator,
                hours=int(current_app.config["INVITATION_HOURS"]),
            )
            if link.purpose == invitation_service.INVITE:
                head = f"'{user.email}' has not accepted the invitation yet: a new invitation link."
            else:
                head = f"Reset link for '{user.email}'." + (
                    " The authenticator is forgotten when it is used." if authenticator else ""
                )
            return "\n".join([head, *_link_lines(link, prefix)])

        _run(act)

    @app.cli.group(name="audit")
    def audit_group() -> None:
        """The audit log: who did what, when, and to what."""

    @audit_group.command(name="list")
    @click.option("--days", type=click.IntRange(1, 3650), help="Only the last N days.")
    @click.option(
        "--group",
        type=click.Choice(sorted(audit_service.GROUPS)),
        help="Only one kind of entry (sign-in, assessment, hosts, scan, finding, export, user).",
    )
    @click.option("--user", help="Only entries of people whose e-mail address contains this.")
    @click.option("--limit", type=click.IntRange(1, 200), default=50, show_default=True)
    def audit_list(days: int | None, group: str | None, user: str | None, limit: int) -> None:
        """Show the newest entries of the audit log (the same as the audit page)."""
        page = audit_service.list_events(
            db.session(),
            group=group,
            actor=user,
            since=utc_now() - timedelta(days=days) if days else None,
            per_page=limit,
        )
        names = audit_service.assessment_names(db.session(), page.items)
        for entry in page.items:
            who = entry.actor_email or ("command line" if entry.source == "cli" else "-")
            domain = names.get(entry.assessment_id) if entry.assessment_id else None
            domain = domain or entry.details.get("domain")
            facts = " ".join(f"{key}={text}" for key, text in audit_service.facts(entry.details))
            line = f"{entry.occurred_at:%Y-%m-%d %H:%M:%S} UTC  {who:28}  "
            line += audit_service.action_label(entry.action)
            click.echo(line + (f"  [{domain}]" if domain else "") + (f"  {facts}" if facts else ""))
        shown = f"{len(page.items)} of {page.total}"
        click.echo(f"{shown} entries." if page.total else "The audit log has no entry for this.")

    @app.cli.command(name="worker")
    @click.option("--once", is_flag=True, help="Process the queued work, then exit.")
    @click.option(
        "--poll-interval",
        default=2.0,
        show_default=True,
        type=click.FloatRange(min=0.1),
        help="Seconds to wait when the queue is empty.",
    )
    @click.option("--worker-id", default=None, help="Name shown in task locks (default: host:pid).")
    @click.option(
        "--threads",
        default=None,
        type=click.IntRange(1, 64),
        help="Checks to run at the same time (default: WORKER_THREADS).",
    )
    def worker(
        once: bool, poll_interval: float, worker_id: str | None, threads: int | None
    ) -> None:
        """Run the scan worker: claim queued checks, run them, store the outcomes."""
        click.echo("Worker started." if not once else "Processing queued work.")
        try:
            processed = worker_service.run_worker(
                app, worker_id=worker_id, once=once, poll_interval=poll_interval, threads=threads
            )
        except KeyboardInterrupt:
            click.echo("Worker stopped.")
            return
        click.echo(f"Processed {processed} task(s).")
