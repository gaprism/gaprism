"""Flask CLI commands: thin entry points that call services."""

import click
from flask import Flask

from app.extensions import db
from app.service import users as user_service


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
