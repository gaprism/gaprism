"""Signed-session setup for route tests; no production authentication bypass."""

import uuid
from datetime import UTC, datetime

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models.auth import User


def login_as(
    client: FlaskClient,
    db_session: Session,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> None:
    user = db_session.get(User, user_id)
    assert user is not None and user.active
    with client.session_transaction() as state:
        state.clear()
        state["_user_id"] = user.fs_uniquifier
        state["_fresh"] = True
        state["fs_paa"] = datetime.now(UTC).timestamp()
        state["workspace_id"] = str(workspace_id)
