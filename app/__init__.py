"""Flask Application Factory module."""

import os

from flask import Flask
from flask_security.datastore import SQLAlchemyUserDatastore

from app.audit import init_audit_log
from app.blueprints.accounts import accounts_bp, invitation_bp
from app.blueprints.assessments import assessments_bp
from app.blueprints.audit import audit_bp
from app.blueprints.core import core_bp
from app.commands import register_cli_commands
from app.config import (
    BaseConfig,
    ConfigurationError,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    resolve_config,
    validate_config,
)
from app.extensions import csrf, db, migrate, security
from app.i18n import init_i18n
from app.logging_redaction import install_log_redaction
from app.models.auth import Role, User
from app.service.auth import register_auth_audit
from app.service.auth.rate_limit import register_auth_rate_limit
from app.service.profile import initials
from app.web import register_error_pages, register_proxy_fix, register_security_headers


def create_app(config_object: str | type[BaseConfig] | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    config_class: type[BaseConfig]

    if config_object is None:
        env_mode = os.environ.get("FLASK_ENV", os.environ.get("APP_ENV", "development")).lower()
        if env_mode == "production":
            config_class = ProductionConfig
        elif env_mode == "testing":
            config_class = TestingConfig
        elif env_mode == "development":
            config_class = DevelopmentConfig
        else:
            raise ConfigurationError(f"Unknown configuration profile: {env_mode}")
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

    config_class = resolve_config(
        config_class, config_object is None or isinstance(config_object, str)
    )
    validate_config(config_class)

    install_log_redaction()  # provider keys travel in URLs: keep them out of every log line
    init_audit_log()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config.from_object(config_class)
    register_proxy_fix(app)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)
    register_auth_rate_limit(app)
    register_auth_audit(app)

    init_i18n(app)
    app.add_template_global(initials, "initials")
    register_security_headers(app)
    register_error_pages(app)

    app.register_blueprint(core_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(accounts_bp)
    app.register_blueprint(invitation_bp)

    register_cli_commands(app)

    return app
