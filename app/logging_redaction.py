"""Keep secrets out of log lines.

Some providers take their key in the URL (Shodan: ``?key=...``) and HTTP libraries like to log
URLs. Every log record is therefore rewritten as it is created: the values of ``key=``,
``token=`` and similar parameters, of ``Authorization`` headers and the password in
``scheme://user:password@host`` URLs become ``REDACTED``. This covers messages, their arguments
and tracebacks, whichever handler later prints them. (Provider code also never puts a key into an
exception message.)
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any

REDACTED = "REDACTED"
_PATTERNS = (
    # ?key=abc&x=1  /  &token=abc  /  apikey=abc  /  api_key: abc  /  secret=abc
    re.compile(
        r"(?i)\b((?:api[_-]?)?key|token|access[_-]?token|secret|password)(\s*[=:]\s*)"
        r"[^\s&;,\"')]+"
    ),
    # Authorization: Bearer abc.def / Authorization: Basic abc
    re.compile(r"(?i)\b(authorization)(\s*[=:]\s*)(?:bearer|basic|token)?\s*[^\s,;\"')]+"),
)
# postgresql+psycopg://user:password@host/db  (the password may contain "@" up to the last one)
_URL_CREDENTIALS = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s/]+(@)")
# The one-time link of an invitation or a reset travels in the path: /auth/invitation/<token>
_LINK_PATH = re.compile(r"(/auth/invitation/)[A-Za-z0-9_-]{16,}")
_install_lock = threading.Lock()
_installed = False


def redact(text: str) -> str:
    """``text`` with the values of secret-looking parameters replaced."""
    for pattern in _PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)
    text = _LINK_PATH.sub(rf"\g<1>{REDACTED}", text)
    return _URL_CREDENTIALS.sub(rf"\g<1>{REDACTED}\g<2>", text)


def install_log_redaction() -> None:
    """Redact every log record created from now on (once per process)."""
    global _installed
    with _install_lock:
        if _installed:
            return
        previous = logging.getLogRecordFactory()

        def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = previous(*args, **kwargs)
            try:
                message = record.getMessage()
            except Exception:
                return record
            redacted = redact(message)
            if redacted != message:
                record.msg, record.args = redacted, None
            if record.exc_info:  # tracebacks carry exception texts: format them now, redacted
                record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            return record

        logging.setLogRecordFactory(factory)
        _installed = True
