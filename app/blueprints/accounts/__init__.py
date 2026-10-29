"""Accounts blueprint: the page where an invited person sets a password with a one-time link."""

from flask import Blueprint

invitation_bp = Blueprint("invitation", __name__, url_prefix="/auth/invitation")

from app.blueprints.accounts import invitation_views  # noqa: E402, F401  (register the routes)
