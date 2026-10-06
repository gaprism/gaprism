"""The audit log's copy in the application log.

Every audit entry (``app.service.audit.record``) goes to the ``audit_event`` table, in the
transaction of the change it records, and as one line to the ``app.audit`` logger, so that a log
collector holds a copy the database does not. INFO records of that logger are written to stderr
unless the deployment configured logging itself.
"""

from __future__ import annotations

import logging

AUDIT_LOGGER = "app.audit"


def init_audit_log(audit: logging.Logger | None = None, root: logging.Logger | None = None) -> None:
    """Make the audit trail visible (idempotent). The loggers are parameters for the tests."""
    audit = audit or logging.getLogger(AUDIT_LOGGER)
    root = root or logging.getLogger()
    audit.setLevel(logging.INFO)
    if not audit.handlers and not root.handlers:  # nobody configured logging
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(message)s"))
        audit.addHandler(handler)
