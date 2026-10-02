"""Flask Application Factory module."""

import os

from flask import Flask, Response, g, jsonify
from flask_security.datastore import SQLAlchemyUserDatastore

from app.blueprints.assessments import assessments_bp
from app.commands import register_cli_commands
from app.config import (
    BaseConfig,
    ConfigurationError,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    validate_config,
)
from app.extensions import csrf, db, migrate, security
from app.models.auth import Role, User


def create_app(config_object: str | type[BaseConfig] | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    config_class: type[BaseConfig]

    if config_object is None:
        env_mode = os.environ.get("FLASK_ENV", os.environ.get("APP_ENV", "development")).lower()
        if env_mode == "production":
            config_class = ProductionConfig
        elif env_mode == "testing":
            config_class = TestingConfig
        else:
            config_class = DevelopmentConfig
    elif isinstance(config_object, str):
        config_map: dict[str, type[BaseConfig]] = {
            "development": DevelopmentConfig,
            "testing": TestingConfig,
            "production": ProductionConfig,
        }
        if config_object.lower() in config_map:
            config_class = config_map[config_object.lower()]
        else:
            raise ConfigurationError(f"Unknown configuration profile: {config_object}")
    elif isinstance(config_object, type) and issubclass(config_object, BaseConfig):
        config_class = config_object
    else:
        raise ConfigurationError("Invalid configuration object provided.")

    validate_config(config_class)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)

    # Register basic security headers
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        return response

    @app.before_request
    def set_test_session() -> None:
        if app.testing and hasattr(app, "_test_db_session") and getattr(app, "_test_db_session", None) is not None:
            g.db_session = getattr(app, "_test_db_session")

    # Register Blueprints
    app.register_blueprint(assessments_bp)

    # Register CLI commands
    register_cli_commands(app)

    # Basic healthcheck endpoint (no DB access, pure uptime check)
    @app.route("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "healthy", "env": app.config.get("ENV")})

    # Default index route
    @app.route("/")
    def index() -> Response:
        return jsonify({"status": "ok", "message": "SaaS Technical Due Diligence Platform"})

    return app
