"""PostgreSQL Row-Level Security (RLS) context management and session scoping."""

import contextlib
from collections.abc import Generator

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.service.access.context import ActorContext

_SETTING_NAMES = ("app.user_id", "app.workspace_id", "app.is_admin")


def _read_context(session: Session) -> dict[str, str]:
    row = session.execute(
        text(
            "SELECT "
            "current_setting('app.user_id', true), "
            "current_setting('app.workspace_id', true), "
            "current_setting('app.is_admin', true)"
        )
    ).one()
    return {name: value or "" for name, value in zip(_SETTING_NAMES, row, strict=True)}


def _write_context(session: Session, values: dict[str, str]) -> None:
    for name in _SETTING_NAMES:
        session.execute(
            text("SELECT set_config(:setting_name, :setting_value, true)"),
            {"setting_name": name, "setting_value": values.get(name, "")},
        )


@contextlib.contextmanager
def set_transaction_actor(
    session: Session, actor: ActorContext | None
) -> Generator[Session, None, None]:
    """Bind a trusted actor to the current transaction and restore prior context.

    PostgreSQL's ``set_config(..., true)`` is transaction-local, so pooled
    connections cannot retain the values after commit or rollback.  Restoring the
    prior values also makes nested service scopes deterministic.
    """
    previous = _read_context(session)
    values = {
        "app.user_id": str(actor.user_id) if actor is not None else "",
        "app.workspace_id": str(actor.workspace_id) if actor is not None else "",
        "app.is_admin": "true" if actor is not None and actor.is_admin else "false",
    }
    _write_context(session, values)

    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            _write_context(session, previous)
