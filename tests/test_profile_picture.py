"""The picture on the profile: stored as ours, shown where the avatar is, served to those who are
signed in, and never kept as it came.

What becomes of the bytes is tests/test_images.py; here are the account that keeps them, the three
routes, the words, and the headers that let a browser keep a picture without caching anything else.
"""

from __future__ import annotations

import hashlib
import io
import re
import uuid

import pytest
from flask import Flask
from flask.testing import FlaskClient
from PIL import Image
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from werkzeug.test import TestResponse

from app.models import User, UserImage
from app.service import images
from app.service import profile as profile_service
from app.service.users import UserAdminError
from tests.helpers import Marked, audit_rows, create_user, login_as, make_app
from tests.test_images import (
    BLUE,
    RED,
    TOO_LARGE,
    TOO_MANY_PIXELS,
    UNREADABLE,
    encoded,
    halves,
    png_claiming,
)
from tests.test_profile_page import avatar, html, signed_in

NO_FILE = "Choose a picture to upload."
LIMIT = 3 * 1024 * 1024  # what a request may hold at all (config MAX_CONTENT_LENGTH)


def jpeg(first: tuple[int, int, int] = RED, second: tuple[int, int, int] = BLUE) -> bytes:
    return encoded(halves((600, 300), first, second), "JPEG")


def send(
    client: FlaskClient, data: bytes, name: str = "me.jpg", follow_redirects: bool = False
) -> TestResponse:
    """Choose a file in the form and press the button."""
    return client.post(
        "/profile/picture",
        data={"picture": (io.BytesIO(data), name)},
        content_type="multipart/form-data",
        follow_redirects=follow_redirects,
    )


def stored(session: Session, user: User) -> UserImage | None:
    return session.scalar(select(UserImage).where(UserImage.user_id == user.id))


def count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def consistent(session: Session, user: User) -> None:
    """The account says it has a picture exactly when there is one, and names that one."""
    session.refresh(user)
    row = stored(session, user)
    if row is None:
        assert user.picture_version is None
    else:
        assert user.picture_version == hashlib.sha256(row.content).hexdigest()[:16]


# ------------------------------------------------------------------------------ the account


def test_a_picture_is_stored_as_ours_and_named_by_what_it_is(db_session: Session) -> None:
    user = create_user(db_session)
    assert profile_service.change_picture(db_session, user, jpeg()) is True

    row = stored(db_session, user)
    assert row is not None
    kept = Image.open(io.BytesIO(row.content))
    assert (kept.format, kept.size) == ("WEBP", (256, 256))  # not the upload
    assert user.picture_version == profile_service.picture_version(row.content)
    assert len(user.picture_version) == 16
    consistent(db_session, user)


def test_a_picture_is_audited_without_the_picture(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    (event,) = audit_rows(db_session, "user.profile_changed")
    assert event.subject == str(user.id)
    assert event.details == {"email": user.email, "picture": "set"}


def test_the_same_picture_again_changes_nothing_and_is_not_audited(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    version = user.picture_version
    assert profile_service.change_picture(db_session, user, jpeg()) is False
    assert user.picture_version == version and count(db_session, UserImage) == 1
    assert len(audit_rows(db_session, "user.profile_changed")) == 1


def test_a_new_picture_replaces_the_old_one_and_the_old_bytes_are_gone(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg(RED, BLUE))
    first = user.picture_version
    assert profile_service.change_picture(db_session, user, jpeg(BLUE, RED)) is True
    assert user.picture_version != first
    assert count(db_session, UserImage) == 1  # replaced, not added to
    consistent(db_session, user)


def test_removing_the_picture_deletes_the_bytes_and_is_audited(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    assert profile_service.remove_picture(db_session, user) is True
    assert user.picture_version is None and count(db_session, UserImage) == 0
    assert audit_rows(db_session, "user.profile_changed")[-1].details["picture"] == "removed"
    assert profile_service.remove_picture(db_session, user) is False  # nothing left to remove
    assert len(audit_rows(db_session, "user.profile_changed")) == 2
    consistent(db_session, user)


def test_a_refused_picture_leaves_the_picture_and_the_log_as_they_were(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    before = user.picture_version
    for refused in (b"not a picture", b"\x00" * (images.MAX_PICTURE_BYTES + 1)):
        with pytest.raises(UserAdminError):
            profile_service.change_picture(db_session, user, refused)
    assert user.picture_version == before and count(db_session, UserImage) == 1
    assert len(audit_rows(db_session, "user.profile_changed")) == 1


def test_the_picture_goes_when_the_account_goes(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    db_session.commit()
    db_session.delete(user)
    db_session.commit()
    assert count(db_session, UserImage) == 0


def test_a_picture_is_found_by_the_account(db_session: Session) -> None:
    user, other = create_user(db_session), create_user(db_session)
    profile_service.change_picture(db_session, user, jpeg())
    found = profile_service.picture_of(db_session, user.id)
    assert found is not None and found.user_id == user.id
    assert profile_service.picture_of(db_session, other.id) is None
    assert profile_service.picture_of(db_session, uuid.uuid4()) is None


# ------------------------------------------------------------------------------ the door


def test_the_three_routes_of_the_picture_need_a_sign_in(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    owner = create_user(db_session)
    profile_service.change_picture(db_session, owner, jpeg())
    db_session.commit()
    for url, method in (
        ("/profile/picture", "post"),
        ("/profile/picture/remove", "post"),
        (f"/profile/picture/{owner.id}", "get"),
    ):
        response = getattr(client, method)(url)
        assert response.status_code == 302 and "/auth/login" in response.headers["Location"], url
    assert count(db_session, UserImage) == 1  # and nobody could take it away


def test_the_forms_of_the_picture_need_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from app.extensions import db

        session = db.session()
        user = create_user(session)
        # Put there by hand: the service would write an audit entry, and this app's session is
        # not cleaned between tests the way the other one is.
        session.add(UserImage(user_id=user.id, content=b"a picture"))
        user.picture_version = "0123456789abcdef"
        session.commit()
        try:
            client = app.test_client()
            login_as(client, user)
            before = user.picture_version
            assert send(client, jpeg(BLUE, RED)).status_code == 400
            assert client.post("/profile/picture/remove").status_code == 400
            session.refresh(user)
            assert user.picture_version == before and count(session, UserImage) == 1
        finally:
            session.delete(user)
            session.commit()


# ------------------------------------------------------------------------------ the page


def test_choosing_a_picture_stores_it_and_says_so(client: FlaskClient, db_session: Session) -> None:
    user = signed_in(client, db_session)
    response = send(client, jpeg(), follow_redirects=True)
    page = html(response)

    assert response.request.path == "/profile/" and "Picture saved." in page
    consistent(db_session, user)
    assert user.picture_version is not None
    assert f'src="/profile/picture/{user.id}?v={user.picture_version}"' in page  # the preview
    (event,) = audit_rows(db_session, "user.profile_changed")
    assert (event.source, event.actor_id) == ("web", user.id)


def test_removing_the_picture_says_so_and_a_second_time_says_there_is_none(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    send(client, jpeg())
    page = html(client.post("/profile/picture/remove", follow_redirects=True))
    assert "Picture removed." in page and 'action="/profile/picture/remove"' not in page
    consistent(db_session, user)
    assert stored(db_session, user) is None

    page = html(client.post("/profile/picture/remove", follow_redirects=True))
    assert "There is no picture to remove." in page
    assert len(audit_rows(db_session, "user.profile_changed")) == 2  # set, removed: no third


def test_the_form_of_the_picture_tells_the_browser_what_it_may_choose(
    client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session)
    page = html(client.get("/profile/"))
    form = re.search(r'<form [^>]*action="/profile/picture"[^>]*>', page)
    assert form is not None and 'enctype="multipart/form-data"' in form.group(0)
    field = re.search(r'<input [^>]*type="file"[^>]*>', page)
    assert field is not None and 'accept="image/jpeg,image/png,image/webp"' in field.group(0)
    assert 'id="picture"' in field.group(0)
    assert 'action="/profile/picture/remove"' not in page  # nothing to remove yet


REFUSALS = [
    pytest.param(None, NO_FILE, id="no file"),
    pytest.param(b"hello, this is text", UNREADABLE, id="not a picture"),
    pytest.param(png_claiming(5000, 5000), TOO_MANY_PIXELS, id="too many pixels"),
    pytest.param(b"\x00" * (images.MAX_PICTURE_BYTES + 1), TOO_LARGE, id="too large"),
]


def refused_page(client: FlaskClient, data: bytes | None) -> tuple[int, str]:
    if data is None:
        response = client.post("/profile/picture", data={}, content_type="multipart/form-data")
    else:
        response = send(client, data)
    return response.status_code, html(response)


@pytest.mark.parametrize(("data", "message"), REFUSALS)
def test_a_refused_picture_says_what_to_do_and_nothing_is_stored(
    client: FlaskClient, db_session: Session, data: bytes | None, message: str
) -> None:
    user = signed_in(client, db_session, name="Anna Meier")
    status, page = refused_page(client, data)

    assert status == 200  # the page again, with its error under the field
    assert f'id="picture-error">{message}</p>' in page
    assert "Picture saved." not in page
    assert 'value="Anna Meier"' in page  # the other form is still there, as it was
    assert user.picture_version is None and count(db_session, UserImage) == 0
    assert audit_rows(db_session, "user.profile_changed") == []


def test_every_refusal_of_the_picture_is_translated_when_it_is_shown(
    client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in(client, db_session)
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    for param in REFUSALS:
        data, message = param.values
        _, page = refused_page(client, data)
        assert f'id="picture-error">[xx] {message}</p>' in page, message

    assert "[xx] Picture saved." in html(send(client, jpeg(), follow_redirects=True))
    removed = html(client.post("/profile/picture/remove", follow_redirects=True))
    assert "[xx] Picture removed." in removed
    again = html(client.post("/profile/picture/remove", follow_redirects=True))
    assert "[xx] There is no picture to remove." in again


def test_a_request_over_the_limit_is_stopped_before_anything_is_read(
    app: Flask, client: FlaskClient, db_session: Session
) -> None:
    assert app.config["MAX_CONTENT_LENGTH"] == LIMIT
    user = signed_in(client, db_session)
    response = send(client, b"\x00" * (LIMIT + 1024))
    assert response.status_code == 413  # type: ignore[attr-defined]
    page = html(response)
    assert "Request too large" in page
    assert "If you were sending a picture, choose a smaller one." in page
    assert user.picture_version is None and count(db_session, UserImage) == 0


# ------------------------------------------------------------------------------ serving it


def url_of(user: User) -> str:
    return f"/profile/picture/{user.id}"


def test_the_picture_is_served_as_the_image_it_is_and_nothing_else(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    send(client, jpeg())
    row = stored(db_session, user)
    assert row is not None

    response = client.get(url_of(user))
    assert response.status_code == 200
    assert response.get_data() == row.content
    assert response.headers["Content-Type"] == "image/webp"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Disposition"] == "inline"
    assert response.headers["Content-Length"] == str(len(row.content))


def test_everybody_who_is_signed_in_may_see_a_picture(
    client: FlaskClient, db_session: Session
) -> None:
    owner = signed_in(client, db_session)
    send(client, jpeg())
    login_as(client, create_user(db_session))
    assert client.get(url_of(owner)).status_code == 200


@pytest.mark.parametrize("who", ["has none", "unknown"])
def test_there_is_nothing_to_serve_without_a_picture(
    client: FlaskClient, db_session: Session, who: str
) -> None:
    signed_in(client, db_session)
    target = f"/profile/picture/{create_user(db_session).id if who == 'has none' else uuid.uuid4()}"
    refused = client.get(target)
    assert refused.status_code == 404
    assert refused.headers["Cache-Control"] == "no-store"  # only the picture itself may be kept


def test_a_browser_may_keep_the_picture_for_as_long_as_its_name_stays(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    send(client, jpeg())
    version = user.picture_version
    assert version is not None

    kept = client.get(f"{url_of(user)}?v={version}")
    assert kept.headers["Cache-Control"] == "private, max-age=31536000, immutable"
    for query in ("", "?v=0000000000000000", "?v="):  # no name, or a name that is out of date
        assert client.get(url_of(user) + query).headers["Cache-Control"] == "private, no-cache"


def test_a_browser_that_has_the_picture_is_told_so(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    send(client, jpeg())
    first = client.get(url_of(user))
    again = client.get(url_of(user), headers={"If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304 and again.get_data() == b""

    send(client, jpeg(BLUE, RED))  # a different picture has a different tag
    other = client.get(url_of(user), headers={"If-None-Match": first.headers["ETag"]})
    assert other.status_code == 200


def test_only_the_picture_may_be_cached_every_page_stays_out_of_every_cache(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    send(client, jpeg())
    for page in ("/profile/", "/assessments/"):
        assert client.get(page).headers["Cache-Control"] == "no-store", page
    assert client.get(url_of(user)).headers["Cache-Control"] != "no-store"


# ------------------------------------------------------------------------------ where it shows


def test_the_avatar_is_the_picture_when_there_is_one_and_the_initials_when_not(
    client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session, email="anna.meier@example.org")
    assert avatar(html(client.get("/assessments/"))) == "AM"

    send(client, jpeg())
    inner = avatar(html(client.get("/assessments/")))
    assert inner == f'<img src="/profile/picture/{user.id}?v={user.picture_version}" alt="">'

    client.post("/profile/picture/remove")
    assert avatar(html(client.get("/assessments/"))) == "AM"


def test_the_list_of_accounts_shows_the_pictures_people_chose(
    client: FlaskClient, db_session: Session
) -> None:
    from app.service import users as user_service

    boss = user_service.create_admin(db_session, "boss@example.org", "Correct-Horse-Battery-1")
    db_session.commit()
    with_picture = create_user(db_session, "with@example.org")
    create_user(db_session, "without@example.org")
    profile_service.change_picture(db_session, with_picture, jpeg())
    db_session.commit()
    login_as(client, boss)

    page = html(client.get("/accounts/"))
    assert f'src="/profile/picture/{with_picture.id}?v={with_picture.picture_version}"' in page
    assert page.count('<img src="/profile/picture/') == 1  # the others have their initials
