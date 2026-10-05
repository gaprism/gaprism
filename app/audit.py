"""The audit trail, until the audit log of story S3.5 exists.

Decisions about findings (accepting, marking as a false positive, reopening) are written to the
``app.audit`` logger: who did what to which finding, never the reason text. The decision row keeps
author, time and history while it exists; reopening deletes it, so this is what remains. INFO
records of that logger are written to stderr unless the deployment configured logging itself.
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
