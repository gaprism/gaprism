"""Sharing an assessment with the team (decision D4) and seeing whose it is."""

from __future__ import annotations

import logging

import pytest
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.service import assessments as assessment_service
from app.service import users as user_service
from tests.helpers import create_assessment, create_user, login_as, make_app


def boss(session: Session) -> object:
    user = user_service.create_admin(session, "boss@example.org", "Administrator-Pass-1")
    session.commit()
    return user


def page(client: FlaskClient, address: str) -> str:
    response = client.get(address)
    assert response.status_code == 200, address
    return response.get_data(as_text=True)


def share(client: FlaskClient, assessment: Assessment, visibility: str) -> int:
    return client.post(
        f"/assessments/{assessment.id}/visibility", data={"visibility": visibility}
    ).status_code


# ------------------------------------------------------------------------------ the rules


def test_the_owner_and_the_administrators_manage_an_assessment_not_the_team(
    db_session: Session,
) -> None:
    owner, colleague = create_user(db_session), create_user(db_session)
    admin = boss(db_session)
    shared = create_assessment(db_session, owner, "shared.example", "team")

    assert assessment_service.can_manage(owner, shared)
    assert assessment_service.can_manage(admin, shared)  # type: ignore[arg-type]
    assert assessment_service.can_access(colleague, shared)  # may work on it ...
    assert not assessment_service.can_manage(colleague, shared)  # ... not decide who sees it


def test_the_owner_of_each_assessment_is_found_with_one_query(db_session: Session) -> None:
    ann, bob = (
        create_user(db_session, "ann@example.org"),
        create_user(db_session, "bob@example.org"),
    )
    first, second = (
        create_assessment(db_session, ann, "a.example"),
        create_assessment(db_session, bob, "b.example"),
    )
    assert assessment_service.owner_emails(db_session, [first, second]) == {
        first.id: "ann@example.org",
        second.id: "bob@example.org",
    }
    assert assessment_service.owner_emails(db_session, []) == {}


def test_sharing_is_refused_when_the_team_already_has_that_domain(db_session: Session) -> None:
    ann, bob = create_user(db_session), create_user(db_session)
    create_assessment(db_session, ann, "vendor.example", "team")
    mine = create_assessment(
        db_session, bob, "vendor.example", "private"
    )  # private: not visible to ann

    with pytest.raises(assessment_service.DuplicateAssessmentError):
        assessment_service.set_visibility(db_session, mine, "team", bob)
    assert mine.visibility == "private"
    with pytest.raises(ValueError, match="Unknown visibility"):
        assessment_service.set_visibility(db_session, mine, "everyone", bob)


def test_the_change_is_logged_with_who_made_it(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    owner = create_user(db_session)
    assessment = create_assessment(db_session, owner, "logged.example")
    with caplog.at_level(logging.INFO, logger="app.audit"):
        assessment_service.set_visibility(db_session, assessment, "team", owner)
        assessment_service.set_visibility(db_session, assessment, "team", owner)  # nothing changed
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("assessment")]
    assert lines == [
        f"assessment visibility: assessment={assessment.id} visibility=team by={owner.id}"
    ]


# ------------------------------------------------------------------------------ the page


def test_the_owner_sees_who_can_open_it_and_can_change_that(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session, "owner@example.org")
    assessment = create_assessment(db_session, owner, "mine.example", "private")
    login_as(client, owner)

    html = page(client, f"/assessments/{assessment.id}")
    assert "Owner: <bdi>owner@example.org</bdi>" in html
    assert "Only the owner and the administrators can open this assessment." in html
    assert 'name="visibility" value="team"' in html and "Share with the team" in html

    assessment.visibility = "team"
    db_session.commit()
    html = page(client, f"/assessments/{assessment.id}")
    assert "Every signed-in user can open this assessment." in html
    assert 'name="visibility" value="private"' in html and "Make private" in html


def test_a_colleague_sees_whose_it_is_but_cannot_change_who_sees_it(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session, "owner@example.org")
    colleague = create_user(db_session, "colleague@example.org")
    assessment = create_assessment(db_session, owner, "shared.example", "team")
    login_as(client, colleague)

    html = page(client, f"/assessments/{assessment.id}")
    assert "owner@example.org" in html and "Make private" not in html
    assert share(client, assessment, "private") == 403  # not even by a hand-made request
    db_session.refresh(assessment)
    assert assessment.visibility == "team"


def test_the_list_says_whose_each_assessment_is(client: FlaskClient, db_session: Session) -> None:
    me = create_user(db_session, "me@example.org")
    colleague = create_user(db_session, "colleague@example.org")
    create_assessment(db_session, me, "mine.example", "private")
    create_assessment(db_session, colleague, "theirs.example", "team")
    login_as(client, me)

    html = page(client, "/assessments/")
    mine = html.split("mine.example")[1].split("</tr>")[0]
    theirs = html.split("theirs.example")[1].split("</tr>")[0]
    assert "You" in mine and "colleague@example.org" not in mine
    assert "<bdi>colleague@example.org</bdi>" in theirs


# ------------------------------------------------------------------------------ the change


def test_the_owner_shares_and_unshares(client: FlaskClient, db_session: Session) -> None:
    owner, colleague = create_user(db_session), create_user(db_session)
    assessment = create_assessment(db_session, owner, "sharing.example", "private")
    login_as(client, owner)

    response = client.post(f"/assessments/{assessment.id}/visibility", data={"visibility": "team"})
    assert response.status_code == 302 and response.headers["Location"].endswith(
        f"/{assessment.id}"
    )
    assert "Shared with the team" in page(client, response.headers["Location"])
    login_as(client, colleague)
    assert (
        client.get(f"/assessments/{assessment.id}").status_code == 200
    )  # now it is theirs to open

    login_as(client, owner)
    assert share(client, assessment, "private") == 302
    login_as(client, colleague)
    assert client.get(f"/assessments/{assessment.id}").status_code == 404  # and now it is not


def test_an_administrator_can_share_anyones_assessment(
    client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    assessment = create_assessment(db_session, owner, "orphaned.example", "private")
    login_as(client, boss(db_session))  # type: ignore[arg-type]
    assert share(client, assessment, "team") == 302
    db_session.refresh(assessment)
    assert assessment.visibility == "team"


def test_somebody_who_cannot_open_it_is_told_nothing(
    client: FlaskClient, db_session: Session
) -> None:
    owner, stranger = create_user(db_session), create_user(db_session)
    assessment = create_assessment(db_session, owner, "hidden.example", "private")
    login_as(client, stranger)
    assert share(client, assessment, "team") == 404  # not 403: it does not exist for them
    db_session.refresh(assessment)
    assert assessment.visibility == "private"


def test_only_the_two_visibilities_are_accepted(client: FlaskClient, db_session: Session) -> None:
    owner = create_user(db_session)
    assessment = create_assessment(db_session, owner, "values.example")
    login_as(client, owner)
    for value in ("everyone", "", "TEAM"):
        assert share(client, assessment, value) == 400, value


def test_a_second_shared_assessment_of_a_domain_is_refused_with_a_message(
    client: FlaskClient, db_session: Session
) -> None:
    ann, bob = create_user(db_session), create_user(db_session)
    create_assessment(db_session, ann, "vendor.example", "team")
    mine = create_assessment(db_session, bob, "vendor.example", "private")
    login_as(client, bob)

    response = client.post(f"/assessments/{mine.id}/visibility", data={"visibility": "team"})
    assert response.status_code == 302
    assert "already has a shared assessment for vendor.example" in page(
        client, response.headers["Location"]
    )
    db_session.refresh(mine)
    assert mine.visibility == "private"


def test_changing_who_sees_an_assessment_needs_a_csrf_token(
    database_url: str, schema_name: str
) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        owner = create_user(db.session())
        assessment = create_assessment(db.session(), owner, "csrf-sharing.example")
        client = app.test_client()
        login_as(client, owner)
        response = client.post(
            f"/assessments/{assessment.id}/visibility", data={"visibility": "team"}
        )
        assert response.status_code == 400
        db.session.refresh(assessment)
        assert assessment.visibility == "private"
        db.session.delete(assessment)
        db.session.delete(owner)
        db.session.commit()


def test_the_visibility_route_only_changes_things(client: FlaskClient, db_session: Session) -> None:
    owner = create_user(db_session)
    assessment = create_assessment(db_session, owner, "readonly.example")
    login_as(client, owner)
    assert client.get(f"/assessments/{assessment.id}/visibility").status_code == 405


# ------------------------------------------------------------------------------ two-factor


def test_every_page_leads_to_the_two_factor_setup(client: FlaskClient, db_session: Session) -> None:
    """MFA may be optional (REQUIRE_MFA): people who want it need a way in."""
    login_as(client, create_user(db_session))
    html = page(client, "/assessments/")
    assert 'href="/auth/tf-setup"' in html and "Two-factor" in html
    setup = client.get("/auth/tf-setup")  # the page Flask-Security serves
    assert setup.status_code == 200 and 'name="two_factor_setup_form"' in setup.get_data(
        as_text=True
    )
