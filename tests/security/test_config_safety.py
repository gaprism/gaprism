"""Configuration is resolved per app and never silently enters debug mode."""

import pytest
from _pytest.monkeypatch import MonkeyPatch

from app import create_app
from app.config import ConfigurationError, TestingConfig


def test_unknown_environment_rejected(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.setenv("APP_ENV", "prodution")
    with pytest.raises(ConfigurationError, match="Unknown configuration profile"):
        create_app()


def test_runtime_key_used_for_mfa(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "fixture-key-a-with-at-least-32-characters")
    first = create_app("testing")
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "fixture-key-b-with-at-least-32-characters")
    second = create_app("testing")
    assert first.config["SECURITY_TOTP_SECRETS"]["1"] == first.config["MFA_ENCRYPTION_KEY"]
    assert first.config["SECURITY_TOTP_SECRETS"] != second.config["SECURITY_TOTP_SECRETS"]
    first.config["SECURITY_LOGOUT_METHODS"].append("FIXTURE")
    assert "FIXTURE" not in second.config["SECURITY_LOGOUT_METHODS"]
    assert "FIXTURE" not in TestingConfig.SECURITY_LOGOUT_METHODS
