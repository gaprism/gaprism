"""Flask CLI commands: thin entry points that call services."""

from pathlib import Path

import click
import httpx
from flask import Flask
from sqlalchemy import select

from app.extensions import db
from app.models import Assessment
from app.rules import RULES
from app.service import findings as findings_service
from app.service import geo as geo_service
from app.service import scans as scan_service
from app.service import users as user_service
from app.service import worker as worker_service


def _megabytes(size: int | None) -> str:
    return f"{(size or 0) / (1024 * 1024):.1f} MB"


def _attribution() -> str:
    return f"Data: {geo_service.ATTRIBUTION} ({geo_service.LICENCE}), {geo_service.ATTRIBUTION_URL}"


def register_cli_commands(app: Flask) -> None:
    """Register custom Click CLI commands with the Flask application."""

    @app.cli.group(name="datasets")
    def datasets_group() -> None:
        """IP location data (DB-IP Lite, installed offline)."""

    @datasets_group.command(name="status")
    def datasets_status() -> None:
        """Show which databases are installed, how old they are and where they came from."""
        directory = Path(app.config["DATASETS_DIR"])
        click.echo(f"Directory: {directory}")
        missing = False
        for item in geo_service.dataset_status(directory):
            if not item.present:
                missing = True
                click.echo(f"  {item.kind}: {item.problem}")
                continue
            age = f"{item.age_days} days old" + (
                " - STALE, run `flask datasets update`" if item.stale else ""
            )
            click.echo(f"  {item.kind}: build {item.build} ({age})")
            click.echo(f"      source: {item.source or 'unknown'}")
            click.echo(f"      sha256: {item.sha256 or 'unknown'}")
        if missing:
            click.echo("Run `flask datasets update` to install the missing data.")
        click.echo(_attribution())

    @datasets_group.command(name="update")
    @click.option(
        "--force", is_flag=True, help="Download again even if this month's build is installed."
    )
    def datasets_update(force: bool) -> None:
        """Download and install the current DB-IP Lite city and ASN databases (about 65 MB)."""
        directory = Path(app.config["DATASETS_DIR"])
        click.echo(f"Installing into {directory} (this can take a minute)...")
        with httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0, read=120.0),
            headers={"User-Agent": str(app.config["USER_AGENT"])},
            trust_env=False,
        ) as client:
            reports = geo_service.update_datasets(directory, client, force=force)
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
        click.echo(_attribution())
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
