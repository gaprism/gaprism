"""Silence one named warning while something the world still serves is read.

Python's ``warnings.catch_warnings`` changes process-wide state, so it is used under one lock for
the whole process: two threads that each silence a different warning must not restore each
other's filters. Used by the TLS prober (certificates with a serial number that is not positive)
and by the protocol prober (offering the deprecated protocol versions on purpose).
"""

from __future__ import annotations

import contextlib
import threading
import warnings
from collections.abc import Iterator

_LOCK = threading.Lock()


@contextlib.contextmanager
def silenced(category: type[Warning], message: str) -> Iterator[None]:
    """Ignore warnings of ``category`` whose text starts with the regular expression ``message``."""
    with _LOCK, warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=message, category=category)
        yield
