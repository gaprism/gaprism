"""Assessments blueprint: list, create and review assessments."""

from flask import Blueprint

assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")

from app.blueprints.assessments import views  # noqa: E402, F401  (registers the routes)
