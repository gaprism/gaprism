"""The page where a signed-in person keeps their own profile."""

from flask import Blueprint

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")

from app.blueprints.profile import views  # noqa: E402, F401  (register the routes)
