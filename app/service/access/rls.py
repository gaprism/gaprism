"""PostgreSQL Row-Level Security (RLS) context management and session scoping."""

import contextlib
from collections.abc import Generator

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.service.access.context import ActorContext


@contextlib.contextmanager
def set_transaction_actor(
    session: Session, actor: ActorContext | None
) -> Generator[Session, None, None]:
    """Set PostgreSQL transaction-local RLS variables to enforce row-level security."""
    if actor is not None:
        is_admin_str = "true" if actor.is_admin else "false"
        session.execute(
            text(
                f"SET LOCAL app.user_id = '{actor.user_id}'; "
                f"SET LOCAL app.workspace_id = '{actor.workspace_id}'; "
                f"SET LOCAL app.is_admin = '{is_admin_str}';"
            )
        )
    else:
        session.execute(
            text(
                "RESET app.user_id; "
                "RESET app.workspace_id; "
                "RESET app.is_admin;"
            )
        )

    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            session.execute(
                text(
                    "RESET app.user_id; "
                    "RESET app.workspace_id; "
                    "RESET app.is_admin;"
                )
            )
