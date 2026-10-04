"""Flask CLI commands: thin entry points that call services."""

import click
from flask import Flask

from app.extensions import db
from app.service import users as user_service
from app.service import worker as worker_service


def register_cli_commands(app: Flask) -> None:
    """Register custom Click CLI commands with the Flask application."""

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
    def worker(once: bool, poll_interval: float, worker_id: str | None) -> None:
        """Run the scan worker: claim queued checks, run them, store the outcomes."""
        click.echo("Worker started." if not once else "Processing queued work.")
        try:
            processed = worker_service.run_worker(
                app, worker_id=worker_id, once=once, poll_interval=poll_interval
            )
        except KeyboardInterrupt:
            click.echo("Worker stopped.")
            return
        click.echo(f"Processed {processed} task(s).")
