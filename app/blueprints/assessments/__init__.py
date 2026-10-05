"""Assessments blueprint: list, create and review assessments."""

from flask import Blueprint

assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")

from app.blueprints.assessments import exports, views  # noqa: E402, F401  (register the routes)
