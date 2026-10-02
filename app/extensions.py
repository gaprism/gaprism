"""Unbound Flask extensions initialized without application context."""

from flask_migrate import Migrate
from flask_security.core import Security
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
csrf: CSRFProtect = CSRFProtect()
security: Security = Security()
