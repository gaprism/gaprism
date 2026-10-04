"""Security regressions that need neither a database nor network access."""

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app import create_app
from app.config import TestingConfig
from app.models.auth import Role, User
from app.service.access.context import ActorContext


def test_forged_test_headers_do_not_authenticate() -> None:
    app = create_app("testing")
    with patch("app.blueprints.assessments.views._get_db") as db_getter:
        response = app.test_client().get(
            f"/assessments/{uuid.uuid4()}",
            headers={
                "X-Test-Actor-Id": str(uuid.uuid4()),
                "X-Test-Workspace-Id": str(uuid.uuid4()),
            },
        )
    assert response.status_code == 401
    db_getter.assert_not_called()


def test_legacy_actor_session_does_not_authenticate() -> None:
    app = create_app("testing")
    client = app.test_client()
    with client.session_transaction() as state:
        state["actor_user_id"] = str(uuid.uuid4())
        state["workspace_id"] = str(uuid.uuid4())
    assert client.get(f"/assessments/{uuid.uuid4()}").status_code == 401


def test_annotation_post_requires_csrf() -> None:
    class CSRFTestingConfig(TestingConfig):
        WTF_CSRF_ENABLED = True

    app = create_app(CSRFTestingConfig)
    response = app.test_client().post(
        f"/assessments/{uuid.uuid4()}/findings/{uuid.uuid4()}/annotate",
        data={"justification": "synthetic"},
    )
    assert response.status_code == 400


def test_actor_context_rejects_nonmember() -> None:
    user = User(id=uuid.uuid4(), email="synthetic@example.com", active=True)
    with pytest.raises(PermissionError):
        ActorContext.from_user(user, uuid.uuid4(), datetime.now(UTC))


def test_admin_role_does_not_bypass_workspace_membership() -> None:
    user = User(
        id=uuid.uuid4(),
        email="admin-without-membership@example.com",
        password="fixture-password",
        active=True,
    )
    user.memberships = []
    user.roles = [Role(name="admin")]
    with pytest.raises(PermissionError):
        ActorContext.from_user(user, uuid.uuid4())
