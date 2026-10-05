"""The audit trail is visible: INFO records of ``app.audit`` are not lost."""

from __future__ import annotations

import logging

from app.audit import AUDIT_LOGGER, init_audit_log


def loggers() -> tuple[logging.Logger, logging.Logger]:
    """An audit logger and a root logger of a process nobody configured (fresh, not the globals)."""
    return logging.Logger("audit.test"), logging.Logger("root.test")


def test_without_any_logging_set_up_the_trail_goes_to_stderr() -> None:
    audit, root = loggers()
    init_audit_log(audit, root)
    assert audit.level == logging.INFO
    assert len(audit.handlers) == 1 and isinstance(audit.handlers[0], logging.StreamHandler)
    init_audit_log(audit, root)  # idempotent
    assert len(audit.handlers) == 1


def test_where_logging_is_configured_the_trail_joins_it() -> None:
    audit, root = loggers()
    root.addHandler(logging.NullHandler())
    init_audit_log(audit, root)
    assert audit.level == logging.INFO  # records are created...
    assert audit.handlers == []  # ...and left to the handlers of the deployment


def test_the_application_makes_the_trail_visible(client: object) -> None:
    assert logging.getLogger(AUDIT_LOGGER).level == logging.INFO
