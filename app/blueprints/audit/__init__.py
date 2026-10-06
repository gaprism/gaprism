"""Audit blueprint: the audit log page, for administrators."""

from flask import Blueprint

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

from app.blueprints.audit import views  # noqa: E402, F401  (register the routes)
