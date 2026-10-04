"""Core routes: entry point and health check."""

from flask import Blueprint, current_app, jsonify, redirect, url_for
from werkzeug.wrappers import Response

core_bp = Blueprint("core", __name__)


@core_bp.get("/")
def index() -> Response:
    """Send people to the assessments list (which asks them to sign in first)."""
    return redirect(url_for("assessments.index"))


@core_bp.get("/healthz")
def healthz() -> Response:
    """Uptime check: no database access, no authentication."""
    return jsonify({"status": "healthy", "env": current_app.config.get("ENV")})
