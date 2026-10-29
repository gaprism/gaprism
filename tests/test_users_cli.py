"""`flask users ...`: how an administrator runs the accounts of the team."""

from __future__ import annotations

import hashlib
import re

from flask.testing import FlaskCliRunner
from flask_security.utils import verify_password
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import UserInvitation
from app.models.auth import User
from app.service import users as user_service

PASSWORD = "Correct-Horse-Battery-1"
TWICE = f"{PASSWORD}\n{PASSWORD}\n"


def run(cli_runner: FlaskCliRunner, *args: str, text: str = "") -> tuple[int, str]:
    result = cli_runner.invoke(args=["users", *args], input=text)
    return result.exit_code, result.output


def account(session: Session, email: str, **fields: object) -> User:
    user = user_service.create_user(
        session, email, PASSWORD, admin=bool(fields.pop("admin", False))
    )
    for name, value in fields.items():
        setattr(user, name, value)
    session.commit()
    return user


# ------------------------------------------------------------------------------ create


def test_create_makes_a_member_and_asks_for_the_password(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "create", "Colleague@Example.org", text=TWICE)
    assert code == 0, output
    assert "Account 'colleague@example.org' created." in output and "administrator" not in output

    user = db_session.query(User).filter_by(email="colleague@example.org").one()
    assert user.active and verify_password(PASSWORD, user.password)
    assert not user_service.holds_admin_role(user)


def test_create_with_admin_makes_an_administrator(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "create", "boss@example.org", "--admin", text=TWICE)
    assert code == 0 and "created as an administrator" in output
    assert user_service.holds_admin_role(
        db_session.query(User).filter_by(email="boss@example.org").one()
    )


def test_create_refuses_an_existing_account_a_short_password_and_a_password_argument(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    account(db_session, "there@example.org")
    code, output = run(cli_runner, "create", "there@example.org", text=TWICE)
    assert code != 0 and "exists already" in output

    code, output = run(cli_runner, "create", "new@example.org", text="short\nshort\n")
    assert code != 0 and "at least 12 characters" in output
    assert db_session.query(User).filter_by(email="new@example.org").count() == 0

    code, output = run(
        cli_runner, "create", "new@example.org", "--password", "Visible-In-Process-List-1"
    )
    assert code != 0 and "No such option '--password'" in output


# ------------------------------------------------------------------------------ list


def test_list_shows_every_account_administrators_first(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "list")
    assert code == 0 and "There are no accounts yet" in output

    account(db_session, "zed@example.org")
    account(db_session, "boss@example.org", admin=True)
    account(db_session, "off@example.org", active=False, tf_primary_method="authenticator")
    code, output = run(cli_runner, "list")
    lines = output.splitlines()
    assert code == 0 and lines[0].startswith("E-mail")
    assert [line.split()[0] for line in lines[1:]] == [
        "boss@example.org",
        "off@example.org",
        "zed@example.org",
    ]
    assert "admin" in lines[1] and "never" in lines[1]
    assert "off" in lines[2] and "yes" in lines[2]  # switched off, authenticator enrolled
    assert PASSWORD not in output and "$argon2" not in output  # nothing secret


# ------------------------------------------------------------------------------ switching off


def test_deactivate_and_activate(cli_runner: FlaskCliRunner, db_session: Session) -> None:
    user = account(db_session, "leaver@example.org")
    code, output = run(cli_runner, "deactivate", "LEAVER@example.org")
    assert code == 0 and "switched off" in output and "administrators can share them" in output
    db_session.refresh(user)
    assert user.active is False

    assert "switched off already" in run(cli_runner, "deactivate", user.email)[1]
    code, output = run(cli_runner, "activate", user.email)
    assert code == 0 and "active again" in output
    db_session.refresh(user)
    assert user.active is True
    assert "active already" in run(cli_runner, "activate", user.email)[1]


def test_the_last_administrator_cannot_be_switched_off_or_demoted(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    boss = account(db_session, "boss@example.org", admin=True)
    for command in ("deactivate", "revoke-admin"):
        code, output = run(cli_runner, command, boss.email)
        assert code != 0 and "last active administrator" in output, command
    db_session.refresh(boss)
    assert boss.active and user_service.holds_admin_role(boss)


# ------------------------------------------------------------------------------ the role


def test_grant_and_revoke_admin(cli_runner: FlaskCliRunner, db_session: Session) -> None:
    account(db_session, "boss@example.org", admin=True)
    user = account(db_session, "second@example.org")

    code, output = run(cli_runner, "grant-admin", user.email)
    assert code == 0 and "is an administrator" in output
    assert "one already" in run(cli_runner, "grant-admin", user.email)[1]
    db_session.refresh(user)
    assert user_service.holds_admin_role(user)

    code, output = run(cli_runner, "revoke-admin", user.email)
    assert code == 0 and "not an administrator any more" in output
    assert "is not an administrator." in run(cli_runner, "revoke-admin", user.email)[1]


# ------------------------------------------------------------------------------ passwords and MFA


def test_set_password_asks_for_it_and_ends_the_sessions(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    user = account(db_session, "forgetful@example.org")
    before = user.fs_uniquifier
    code, output = run(
        cli_runner, "set-password", user.email, text="Brand-New-Password-9\nBrand-New-Password-9\n"
    )
    assert code == 0 and "sessions have ended" in output
    db_session.refresh(user)
    assert verify_password("Brand-New-Password-9", user.password) and user.fs_uniquifier != before


def test_reset_mfa_forgets_the_authenticator(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    user = account(
        db_session, "lost-phone@example.org", tf_primary_method="authenticator", tf_totp_secret="S"
    )
    code, output = run(cli_runner, "reset-mfa", user.email)
    assert code == 0 and "is forgotten" in output
    db_session.refresh(user)
    assert user.tf_primary_method is None and user.tf_totp_secret is None
    assert "had no authenticator" in run(cli_runner, "reset-mfa", user.email)[1]


def test_a_mistake_in_the_address_is_told_before_a_password_is_asked(
    cli_runner: FlaskCliRunner,
) -> None:
    """No input is given: asking for the password would fail with "Aborted" instead."""
    code, output = run(cli_runner, "create", "not-an-address")
    assert code != 0 and "valid e-mail address" in output and "Password" not in output
    code, output = run(cli_runner, "set-password", "nobody@example.org")
    assert code != 0 and "no account" in output and "Password" not in output


def test_every_command_says_so_when_there_is_no_such_account(cli_runner: FlaskCliRunner) -> None:
    for command in ("deactivate", "activate", "grant-admin", "revoke-admin", "reset-mfa"):
        code, output = run(cli_runner, command, "nobody@example.org")
        assert code != 0 and "no account" in output, command
    code, output = run(cli_runner, "set-password", "nobody@example.org", text=TWICE)
    assert code != 0 and "no account" in output


# ------------------------------------------------------------------------------ links

BASE = "https://dd.example.org"
TOKEN = re.compile(r"/auth/invitation/([A-Za-z0-9_-]{43})")


def printed_token(output: str) -> str:
    found = TOKEN.search(output)
    assert found, f"no link in: {output}"
    return found.group(1)


def test_invite_creates_an_account_and_prints_the_link_once(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "invite", "New@Example.org", "--admin", "--base-url", BASE + "/")
    assert code == 0, output
    assert "Invited 'new@example.org' as an administrator" in output
    assert f"{BASE}/auth/invitation/" in output and "valid until" in output

    user = db_session.query(User).filter_by(email="new@example.org").one()
    assert user.active and user_service.holds_admin_role(user)
    token = printed_token(output)
    row = db_session.scalars(select(UserInvitation)).one()
    assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in user.password  # only the hash of the link is kept, nothing else

    assert "invited" in run(cli_runner, "list")[1].splitlines()[1]


def test_invite_without_a_base_url_prints_the_path_and_says_to_add_the_address(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "invite", "member@example.org")
    assert code == 0 and "as a member" in output
    assert "address of your site" in output
    assert output.strip().splitlines()[-1].startswith("/auth/invitation/")


def test_invite_refuses_an_existing_account_and_a_bad_address_or_base_url(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    account(db_session, "there@example.org")
    code, output = run(cli_runner, "invite", "there@example.org")
    assert code != 0 and "exists already" in output
    code, output = run(cli_runner, "invite", "not-an-address")
    assert code != 0 and "valid e-mail address" in output
    code, output = run(cli_runner, "invite", "x@example.org", "--base-url", "dd.example.org")
    assert code != 0 and "must start with" in output
    assert db_session.query(User).filter_by(email="x@example.org").count() == 0


def test_reset_link_for_an_account_and_with_the_authenticator_option(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    user = account(db_session, "lost@example.org", tf_primary_method="authenticator")
    code, output = run(cli_runner, "reset-link", user.email, "--base-url", BASE)
    assert code == 0 and "Reset link for 'lost@example.org'" in output
    assert "authenticator" not in output and f"{BASE}/auth/invitation/" in output

    code, output = run(cli_runner, "reset-link", user.email, "--authenticator", "--base-url", BASE)
    assert code == 0 and "authenticator is forgotten when it is used" in output
    assert db_session.scalars(select(UserInvitation)).one().reset_authenticator is True
    db_session.refresh(user)
    assert user.tf_primary_method == "authenticator"  # nothing changes until the link is used


def test_reset_link_for_an_invited_account_is_a_new_invitation(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    run(cli_runner, "invite", "new@example.org")
    code, output = run(cli_runner, "reset-link", "new@example.org")
    assert code == 0 and "has not accepted the invitation yet" in output
    assert db_session.scalars(select(UserInvitation)).one().purpose == "invite"


def test_reset_link_says_so_when_there_is_no_such_account_or_it_is_switched_off(
    cli_runner: FlaskCliRunner, db_session: Session
) -> None:
    code, output = run(cli_runner, "reset-link", "nobody@example.org")
    assert code != 0 and "no account" in output
    off = account(db_session, "off@example.org", active=False)
    code, output = run(cli_runner, "reset-link", off.email)
    assert code != 0 and "switched off" in output


def test_a_password_is_never_an_argument_of_the_link_commands(
    cli_runner: FlaskCliRunner,
) -> None:
    for command in ("invite", "reset-link"):
        code, output = run(
            cli_runner, command, "x@example.org", "--password", "Visible-1-Long-Pass"
        )
        assert code != 0 and "No such option '--password'" in output
