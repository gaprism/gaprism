"""The account screen: administrators only, one thin route per action, a link shown once.

Everything the screen does is the service's work, which has its own tests; here are the doors:
who may knock, what each knock does, what is audited and what the page leaves out."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta

import pytest
from flask import Flask, g
from flask.testing import FlaskClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, User, UserInvitation
from app.models.auth import Role
from app.models.base import utc_now
from app.service import invitations
from app.service import users as user_service
from tests.helpers import NEUTRAL_BADGE, audit_rows, badge_classes, create_user, login_as, make_app

PASSWORD = "Correct-Horse-Battery-1"
TOKEN = re.compile(r"/auth/invitation/([A-Za-z0-9_-]{43})")
SCREEN = {
    "accounts.index",
    "accounts.invite",
    "accounts.make_link",
    "accounts.withdraw",
    "accounts.set_active",
    "accounts.set_admin",
    "accounts.sign_out",
}


def boss(session: Session, email: str = "boss@example.org") -> User:
    user = user_service.create_admin(session, email, PASSWORD)
    session.commit()
    return user


def member(session: Session, email: str = "member@example.org") -> User:
    user = user_service.create_user(session, email, PASSWORD)
    session.commit()
    return user


def signed_in_boss(client: FlaskClient, session: Session) -> User:
    user = boss(session)
    login_as(client, user)
    return user


def html(response: object) -> str:
    return response.get_data(as_text=True)  # type: ignore[attr-defined,no-any-return]


def token_in(page: str) -> str:
    found = TOKEN.search(page)
    assert found, "the page shows no link"
    return found.group(1)


def counts(session: Session) -> tuple[int, int, int]:
    return tuple(  # type: ignore[return-value]
        session.scalar(select(func.count()).select_from(model)) or 0
        for model in (User, UserInvitation, AuditEvent)
    )


# ------------------------------------------------------------------------------ who may knock


def test_only_administrators_see_the_screen(client: FlaskClient, db_session: Session) -> None:
    anonymous = client.get("/accounts/")
    assert anonymous.status_code == 302 and "/auth/login" in anonymous.headers["Location"]

    login_as(client, member(db_session))
    assert client.get("/accounts/").status_code == 404  # nothing here to confirm

    login_as(client, boss(db_session))
    assert client.get("/accounts/").status_code == 200


def test_every_route_of_the_screen_needs_an_administrator(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    rules = [rule for rule in app.url_map.iter_rules() if rule.endpoint.startswith("accounts.")]
    assert {rule.endpoint for rule in rules} == SCREEN  # a new route must be added to this test

    target = member(db_session, "target@example.org")
    login_as(client, member(db_session, "other@example.org"))
    before = counts(db_session)
    for rule in rules:
        url = re.sub(r"<uuid:[a-z_]+>", str(target.id), rule.rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            data = {"email": "x@example.org", "active": "0", "admin": "1", "authenticator": "1"}
            response = client.open(url, method=method, data=data)
            assert response.status_code == 404, (method, url)
    assert counts(db_session) == before  # and nothing happened

    with client.session_transaction() as state:  # signed out: the same doors lead to the sign-in
        state.clear()
    g.pop("_login_user", None)  # one app context for the whole test: forget the cached user
    for rule in rules:
        url = re.sub(r"<uuid:[a-z_]+>", str(target.id), rule.rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = client.open(url, method=method, data={"email": "x@example.org"})
            assert response.status_code == 302, (method, url)
            assert "/auth/login" in response.headers["Location"]
    assert counts(db_session) == before


def test_the_navigation_entry_is_for_administrators_only(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, member(db_session))
    assert 'href="/accounts/"' not in html(client.get("/assessments/"))
    login_as(client, boss(db_session))
    assert 'href="/accounts/"' in html(client.get("/assessments/"))


# ------------------------------------------------------------------------------ the list


def test_the_list_shows_each_account_with_its_state(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_boss(client, db_session)
    now = utc_now()
    member(db_session, "active@example.org")
    off = member(db_session, "off@example.org")
    user_service.set_active(db_session, off.email, False)
    invitations.invite_user(db_session, "open@example.org", admin=False, hours=72, now=now)
    invitations.invite_user(
        db_session, "stale@example.org", admin=False, hours=1, now=now - timedelta(hours=2)
    )
    invitations.invite_user(db_session, "gone@example.org", admin=False, hours=72, now=now)
    invitations.revoke_links(db_session, "gone@example.org", now=now)
    member(db_session, "reset@example.org")
    invitations.new_link(db_session, "reset@example.org", authenticator=False, hours=72, now=now)
    db_session.commit()

    page = html(client.get("/accounts/"))
    for address in ("boss@example.org", "active@example.org", "off@example.org"):
        assert address in page
    for text in (
        "Switched off",
        "Invited, link valid until",
        "Invited, link expired",
        "Invited, link withdrawn",
        "Reset link valid until",
    ):
        assert text in page, text
    assert badge_classes(page, "Active") == NEUTRAL_BADGE  # a state, not a result of a check
    assert TOKEN.search(page) is None  # a list never shows a link


# ------------------------------------------------------------------------------ links


def test_inviting_shows_the_link_once(client: FlaskClient, db_session: Session) -> None:
    admin = signed_in_boss(client, db_session)
    response = client.post(
        "/accounts/invite", data={"email": " New@Example.org ", "admin": "y", "submit": "1"}
    )
    page = html(response)
    assert response.status_code == 200 and "http://localhost/auth/invitation/" in page
    token = token_in(page)

    user = db_session.query(User).filter_by(email="new@example.org").one()
    assert user_service.holds_admin_role(user)
    row = db_session.scalars(select(UserInvitation)).one()
    assert row.created_by == admin.id and token not in str(row.__dict__)
    assert audit_rows(db_session, "user.invited")[0].actor_id == admin.id

    assert token not in html(client.get("/accounts/"))  # shown once
    assert invitations.open_link(db_session, token).user_id == user.id


def test_inviting_an_existing_address_says_so_and_creates_nothing(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_boss(client, db_session)
    member(db_session, "there@example.org")
    before = counts(db_session)
    response = client.post("/accounts/invite", data={"email": "THERE@example.org"})
    assert response.status_code == 302
    assert "exists already" in html(client.get(response.headers["Location"]))
    assert counts(db_session) == before

    response = client.post("/accounts/invite", data={"email": ""})
    assert response.status_code == 302 and counts(db_session) == before


def test_sending_a_link_again_withdraws_the_first(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    user, first = invitations.invite_user(db_session, "new@example.org", admin=False, hours=72)
    db_session.commit()
    response = client.post(f"/accounts/{user.id}/link")
    second = token_in(html(response))
    assert response.status_code == 200 and second != first.token
    with pytest.raises(invitations.InvalidLinkError):
        invitations.open_link(db_session, first.token)
    assert invitations.open_link(db_session, second).purpose == "invite"


def test_a_reset_link_with_the_authenticator_tick(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    lost = member(db_session, "lost@example.org")
    plain = html(client.post(f"/accounts/{lost.id}/link"))
    assert "will be forgotten" not in plain

    ticked = html(client.post(f"/accounts/{lost.id}/link", data={"authenticator": "1"}))
    assert "will be forgotten" in ticked
    row = db_session.scalars(select(UserInvitation)).one()
    assert row.purpose == "reset" and row.reset_authenticator is True
    db_session.refresh(lost)
    assert lost.tf_primary_method is None and lost.password  # nothing changed yet


def test_withdraw_removes_the_link_and_says_so(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    user, link = invitations.invite_user(db_session, "new@example.org", admin=False, hours=72)
    db_session.commit()
    response = client.post(f"/accounts/{user.id}/withdraw")
    assert response.status_code == 302
    assert "Withdrew the link" in html(client.get(response.headers["Location"]))
    with pytest.raises(invitations.InvalidLinkError):
        invitations.open_link(db_session, link.token)
    again = html(client.get(client.post(f"/accounts/{user.id}/withdraw").headers["Location"]))
    assert "no working link" in again


def test_a_link_for_a_switched_off_account_is_refused(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in_boss(client, db_session)
    off = member(db_session, "off@example.org")
    user_service.set_active(db_session, off.email, False)
    response = client.post(f"/accounts/{off.id}/link")
    assert response.status_code == 302
    assert "switched off" in html(client.get(response.headers["Location"]))
    assert db_session.scalars(select(UserInvitation)).first() is None


# ------------------------------------------------------------------------------ the other actions


def test_switching_an_account_off_and_on(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    user = member(db_session)
    client.post(f"/accounts/{user.id}/active", data={"active": "0"})
    db_session.refresh(user)
    assert user.active is False
    assert "switched off" in html(client.get("/accounts/"))

    client.post(f"/accounts/{user.id}/active", data={"active": "1"})
    db_session.refresh(user)
    assert user.active is True


def test_giving_and_taking_the_administrator_role(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    user = member(db_session)
    client.post(f"/accounts/{user.id}/admin", data={"admin": "1"})
    db_session.refresh(user)
    assert user_service.holds_admin_role(user)
    client.post(f"/accounts/{user.id}/admin", data={"admin": "0"})
    db_session.refresh(user)
    assert not user_service.holds_admin_role(user)
    assert len(audit_rows(db_session, "user.admin_granted", "user.admin_revoked")) == 2


def test_the_last_administrator_cannot_be_locked_out_here(
    client: FlaskClient, db_session: Session
) -> None:
    me = signed_in_boss(client, db_session)  # the only administrator
    for url, data in (
        (f"/accounts/{me.id}/active", {"active": "0"}),
        (f"/accounts/{me.id}/admin", {"admin": "0"}),
    ):
        response = client.post(url, data=data)
        assert "last active administrator" in html(client.get(response.headers["Location"]))
    db_session.refresh(me)
    assert me.active and user_service.holds_admin_role(me)


def test_signing_an_account_out_everywhere(
    client: FlaskClient, db_session: Session, app: Flask
) -> None:
    admin = signed_in_boss(client, db_session)
    user = member(db_session)
    person = app.test_client()
    login_as(person, user)
    assert person.get("/assessments/").status_code == 200  # signed in on another device
    before = user.fs_uniquifier

    g.pop("_login_user", None)  # one application context serves every request of this test
    response = client.post(f"/accounts/{user.id}/sign-out")
    assert response.status_code == 302
    db_session.refresh(user)
    assert user.fs_uniquifier != before
    (event,) = audit_rows(db_session, "user.sessions_ended")
    assert event.actor_id == admin.id and event.subject == str(user.id)

    g.pop("_login_user", None)
    ended = person.get("/assessments/")  # the session carried the old identifier
    assert ended.status_code == 302 and "/auth/login" in ended.headers["Location"]


def test_an_account_that_does_not_exist_is_a_404(client: FlaskClient, db_session: Session) -> None:
    signed_in_boss(client, db_session)
    for action, data in (
        ("link", {}),
        ("withdraw", {}),
        ("active", {"active": "0"}),
        ("admin", {"admin": "1"}),
        ("sign-out", {}),
    ):
        assert client.post(f"/accounts/{uuid.uuid4()}/{action}", data=data).status_code == 404


def test_own_row_has_no_button_that_ends_own_access(
    client: FlaskClient, db_session: Session
) -> None:
    me = signed_in_boss(client, db_session)
    other = member(db_session)
    page = html(client.get("/accounts/"))
    for action in ("active", "admin", "sign-out"):
        assert f"/accounts/{me.id}/{action}" not in page, action
        assert f"/accounts/{other.id}/{action}" in page, action
    assert f"/accounts/{me.id}/link" in page  # a reset link for oneself is harmless


def test_the_forms_need_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        session = db.session()
        admin = create_user(session)
        role = session.scalar(select(Role).where(Role.name == user_service.ADMIN_ROLE))
        admin.roles.append(role or Role(name=user_service.ADMIN_ROLE))
        victim = create_user(session)
        session.commit()
        try:
            client = app.test_client()
            login_as(client, admin)
            assert (
                client.post(f"/accounts/{victim.id}/active", data={"active": "0"}).status_code
                == 400
            )
            assert (
                client.post("/accounts/invite", data={"email": "x@example.org"}).status_code == 400
            )
            session.refresh(victim)
            assert victim.active is True
            assert session.query(User).filter_by(email="x@example.org").count() == 0
        finally:
            session.delete(victim)
            session.delete(admin)
            session.commit()
