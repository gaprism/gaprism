"""Flask CLI commands for user administration and system bootstrapping."""

import click
from flask import Flask
from flask_security.utils import hash_password

from app.extensions import db
from app.models.auth import Membership, Role, User, Workspace


def register_cli_commands(app: Flask) -> None:
    """Register custom Click CLI commands with the Flask application."""

    @app.cli.group(name="users")
    def users_group() -> None:
        """User and identity administrative management commands."""
        pass

    @users_group.command(name="create-admin")
    @click.option("--email", prompt="Admin Email", help="Admin email address.")
    @click.option(
        "--password",
        prompt="Admin Password",
        hide_input=True,
        confirmation_prompt=True,
        help="Admin password.",
    )
    @click.option(
        "--workspace",
        "workspace_name",
        default="Default Workspace",
        help="Name of the initial workspace.",
    )
    def create_admin(email: str, password: str, workspace_name: str) -> None:
        """Create or update a local administrator account and assign default workspace."""
        clean_email = email.strip().lower()
        if not clean_email:
            click.echo("Error: Email cannot be empty.", err=True)
            return

        if not password:
            click.echo("Error: Password cannot be empty.", err=True)
            return

        # Ensure admin & member roles exist
        admin_role = db.session.query(Role).filter_by(name="admin").first()
        if not admin_role:
            admin_role = Role(name="admin", description="System Administrator")
            db.session.add(admin_role)

        member_role = db.session.query(Role).filter_by(name="member").first()
        if not member_role:
            member_role = Role(name="member", description="Team Member")
            db.session.add(member_role)

        db.session.flush()

        # Ensure workspace exists
        workspace = db.session.query(Workspace).filter_by(name=workspace_name).first()
        if not workspace:
            workspace = Workspace(name=workspace_name, enabled=True)
            db.session.add(workspace)
            db.session.flush()

        # Find or create user
        user = db.session.query(User).filter_by(email=clean_email).first()
        if user:
            user.password = hash_password(password)
            user.active = True
            if admin_role not in user.roles:
                user.roles.append(admin_role)
        else:
            user = User(
                email=clean_email,
                password=hash_password(password),
                active=True,
            )
            user.roles.append(admin_role)
            db.session.add(user)
            db.session.flush()

        # Ensure active admin membership in the workspace
        membership = (
            db.session.query(Membership)
            .filter_by(workspace_id=workspace.id, user_id=user.id)
            .first()
        )
        if membership:
            membership.role = "admin"
            membership.active = True
        else:
            membership = Membership(
                workspace_id=workspace.id,
                user_id=user.id,
                role="admin",
                active=True,
            )
            db.session.add(membership)

        db.session.commit()
        click.echo(
            f"Successfully bootstrapped admin account '{clean_email}' in "
            f"workspace '{workspace_name}'."
        )
