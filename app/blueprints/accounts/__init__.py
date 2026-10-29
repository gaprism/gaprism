"""Accounts blueprints: the administrator's screen, and the page where an invited person sets a
password with a one-time link."""

from flask import Blueprint

accounts_bp = Blueprint("accounts", __name__, url_prefix="/accounts")
invitation_bp = Blueprint("invitation", __name__, url_prefix="/auth/invitation")

from app.blueprints.accounts import (  # noqa: E402, F401  (register the routes)
    invitation_views,
    views,
)
