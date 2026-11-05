"""The language of the pages, and the entry in the account menu that chooses it.

The order of choice is the account's, then the browser session's, then the language of the browser,
then the first language that the installation offers. A language is named in its own words, and
with its region only where two of the offered languages are one language.

The application has no German catalogue yet. The tests write a small real one (a compiled .mo with
a few sentences) into a temporary folder and point the application at it, so that the whole path
is run: the choice, the translation, the language of the page and the menu.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from babel.messages import Catalog
from babel.messages.mofile import write_mo
from flask import Flask, g
from flask.testing import FlaskClient
from sqlalchemy.orm import Session
from werkzeug.test import TestResponse

from app.i18n import Language, english, gettext, language_choices, language_names
from app.service import profile as profile_service
from app.service.users import UserAdminError
from tests.helpers import Marked, audit_rows, create_user, login_as, make_app
from tests.test_profile_page import html, menu, signed_in

OFFERED = ["en", "de_CH"]
GERMAN = {"Profile": "Profil", "Language": "Sprache", "Sign in": "Anmelden", "Password": "Passwort"}
UNKNOWN = "That language is not available. Choose one from the list."


@pytest.fixture
def german(app: Flask, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """An installation that offers English and de_CH, with a small catalogue for de_CH."""
    catalog = Catalog(locale="de_CH")
    for source, translated in GERMAN.items():
        catalog.add(source, translated)
    folder = tmp_path / "de_CH" / "LC_MESSAGES"
    folder.mkdir(parents=True)
    with (folder / "messages.mo").open("wb") as stream:
        write_mo(stream, catalog)
    monkeypatch.setattr("app.i18n.TRANSLATIONS_DIR", tmp_path)
    monkeypatch.setitem(app.config, "LANGUAGES", OFFERED)
    return app


def forget_the_language() -> None:
    """One application context serves a whole test, and the language of a request is kept on ``g``:
    forget it, as ``login_as`` forgets the user, so that every request chooses for itself."""
    g.pop("_translations", None)


def get(client: FlaskClient, url: str, **options: object) -> TestResponse:
    forget_the_language()
    return client.get(url, **options)  # type: ignore[arg-type]


def post(client: FlaskClient, url: str, **options: object) -> TestResponse:
    forget_the_language()
    return client.post(url, **options)  # type: ignore[arg-type]


def page_language(page: str) -> str:
    found = re.search(r'<html lang="([^"]+)"', page)
    assert found, "the page does not say what language it is in"
    return found.group(1)


def choose(client: FlaskClient, code: str, **fields: str) -> TestResponse:
    return post(client, "/profile/language", data={"locale": code, **fields})


# ------------------------------------------------------------------------------ the names


@pytest.mark.parametrize(
    ("offered", "names"),
    [
        (["en"], {"en": "English"}),
        (["en", "de_CH"], {"en": "English", "de_CH": "Deutsch"}),  # one German: no region
        (
            ["en", "de_CH", "de_DE"],
            {"en": "English", "de_CH": "Deutsch (Schweiz)", "de_DE": "Deutsch (Deutschland)"},
        ),
        (
            ["de_CH", "fr_CH"],
            {"de_CH": "Deutsch", "fr_CH": "Fran\N{LATIN SMALL LETTER C WITH CEDILLA}ais"},
        ),
        (["en", "zz"], {"en": "English", "zz": "zz"}),  # a code Babel does not know stays as it is
    ],
)
def test_a_language_is_named_in_its_own_words_and_the_region_only_where_it_tells_two_apart(
    offered: list[str], names: dict[str, str]
) -> None:
    assert language_names(offered) == names


def test_there_is_nothing_to_choose_while_only_one_language_is_offered() -> None:
    assert language_choices(["en"], "en") == []
    assert language_choices([], "en") == []


def test_the_choices_name_the_languages_and_mark_the_one_in_use() -> None:
    assert language_choices(OFFERED, "de_CH") == [
        Language("en", "English", False),
        Language("de_CH", "Deutsch", True),
    ]


# ------------------------------------------------------------------------------ the order


CASES = [
    pytest.param("de_CH", None, "en", OFFERED, "de-CH", id="the account beats the browser"),
    pytest.param("de_CH", "en", "en", OFFERED, "de-CH", id="the account beats the session"),
    pytest.param(None, "de_CH", "en", OFFERED, "de-CH", id="the session beats the browser"),
    pytest.param(
        None, "en", "de-CH", OFFERED, "en", id="the session beats the browser, the other way"
    ),
    pytest.param(None, None, "de-CH,de;q=0.9,en;q=0.5", OFFERED, "de-CH", id="the browser"),
    pytest.param(None, None, "de-DE,de;q=0.9,en;q=0.5", OFFERED, "de-CH", id="the language alone"),
    pytest.param(None, None, "fr-CH,fr;q=0.9", OFFERED, "en", id="no match: the first language"),
    pytest.param(None, None, None, OFFERED, "en", id="no header at all"),
    pytest.param("fr_CH", None, "en", OFFERED, "en", id="an account language that is not offered"),
    pytest.param("de_CH", None, "de-CH", ["en"], "en", id="an installation with English only"),
    pytest.param(None, "de_CH", "de-CH", ["en"], "en", id="a session language not offered"),
]


@pytest.mark.parametrize(("account", "remembered", "browser", "offered", "expected"), CASES)
def test_the_language_is_chosen_in_this_order(
    german: Flask,
    client: FlaskClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    account: str | None,
    remembered: str | None,
    browser: str | None,
    offered: list[str],
    expected: str,
) -> None:
    monkeypatch.setitem(german.config, "LANGUAGES", offered)
    if account is None:
        url, heading = "/auth/login", ("Sign in", "Anmelden")
    else:
        signed_in(client, db_session, locale=account)
        url, heading = "/profile/", ("Profile", "Profil")
    if remembered is not None:
        with client.session_transaction() as state:  # after login_as, which starts a clean session
            state["locale"] = remembered
    headers = {"Accept-Language": browser} if browser else {}

    page = html(get(client, url, headers=headers))
    assert page_language(page) == expected
    assert f"<h1>{heading[1] if expected == 'de-CH' else heading[0]}</h1>" in page


def test_an_account_that_cannot_be_read_does_not_stop_a_page_from_being_written(
    german: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the database down the account cannot be loaded, and the error page that says so still
    has to be written: in the language the browser asks for, as for anybody who is not signed in."""

    class Unreadable:
        @property
        def is_authenticated(self) -> bool:
            raise RuntimeError("the database is down")

    monkeypatch.setattr("app.i18n.current_user", Unreadable())
    page = html(get(client, "/no-such-page", headers={"Accept-Language": "de-CH"}))
    assert page_language(page) == "de-CH"
    assert "Not found" in page


# ------------------------------------------------------------------------------ the account


def test_a_language_is_kept_with_the_account_and_audited(db_session: Session) -> None:
    user = create_user(db_session)
    assert profile_service.change_locale(db_session, user, "de_CH", OFFERED) is True
    assert user.locale == "de_CH"
    (event,) = audit_rows(db_session, "user.profile_changed")
    assert event.subject == str(user.id)
    assert event.details == {"email": user.email, "locale": "de_CH"}


def test_the_same_language_again_changes_nothing_and_is_not_audited(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_locale(db_session, user, "en", OFFERED)  # English may be chosen too
    assert profile_service.change_locale(db_session, user, "en", OFFERED) is False
    assert len(audit_rows(db_session, "user.profile_changed")) == 1


@pytest.mark.parametrize("code", ["fr_CH", "", "de-CH", "DE_CH", "de_CH; drop table", "x" * 40])
def test_a_language_that_is_not_offered_is_refused_in_one_sentence(
    db_session: Session, code: str
) -> None:
    user = create_user(db_session)
    with pytest.raises(UserAdminError) as refused:
        profile_service.change_locale(db_session, user, code, OFFERED)
    assert (refused.value.message, refused.value.params) == (UNKNOWN, {})
    assert user.locale is None and audit_rows(db_session, "user.profile_changed") == []


# ------------------------------------------------------------------------------ the door


def test_choosing_a_language_needs_a_sign_in(german: Flask, client: FlaskClient) -> None:
    response = choose(client, "de_CH")
    assert response.status_code == 302 and "/auth/login" in response.headers["Location"]


def test_choosing_a_language_needs_a_csrf_token(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True, LANGUAGES=OFFERED)
    with app.app_context():
        from app.extensions import db

        session = db.session()
        user = create_user(session)
        try:
            client = app.test_client()
            login_as(client, user)
            assert client.post("/profile/language", data={"locale": "de_CH"}).status_code == 400
            session.refresh(user)
            assert user.locale is None
        finally:
            session.delete(user)
            session.commit()


# ------------------------------------------------------------------------------ the choice


def test_choosing_a_language_keeps_it_with_the_account_and_in_this_browser(
    german: Flask, client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session)
    response = choose(client, "de_CH", next="/assessments/")

    assert response.status_code == 302 and response.headers["Location"].endswith("/assessments/")
    db_session.refresh(user)
    assert user.locale == "de_CH"
    with client.session_transaction() as state:
        assert state["locale"] == "de_CH"
    assert (
        page_language(html(get(client, "/profile/"))) == "de-CH"
    )  # from now on, whatever the browser says
    (event,) = audit_rows(db_session, "user.profile_changed")
    assert (event.source, event.actor_id) == ("web", user.id)


def test_the_sign_in_page_speaks_the_language_that_was_chosen_in_this_browser(
    german: Flask, client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session)
    choose(client, "de_CH")
    post(client, "/auth/logout")
    page = html(get(client, "/auth/login"))
    assert page_language(page) == "de-CH" and "<h1>Anmelden</h1>" in page


@pytest.mark.parametrize(
    ("sent", "goes_to"),
    [
        pytest.param("/assessments/?x=1", "/assessments/?x=1", id="a page of the application"),
        pytest.param("/profile/", "/profile/", id="the profile"),
        pytest.param(None, "/profile/", id="nothing sent"),
        pytest.param("", "/profile/", id="empty"),
        pytest.param("https://evil.example/x", "/profile/", id="another site"),
        pytest.param("//evil.example/x", "/profile/", id="a link that borrows the scheme"),
        pytest.param(
            "/\\evil.example", "/profile/", id="a backslash that a browser reads as a slash"
        ),
        pytest.param("javascript:alert(1)", "/profile/", id="a script"),
        pytest.param("/no-such-page", "/profile/", id="a page that does not exist"),
        pytest.param("/profile/picture", "/profile/", id="a page that cannot be opened with a GET"),
        pytest.param("/profile/language", "/profile/", id="this very route"),
        pytest.param("/assessments/\r\nSet-Cookie: x=1", "/profile/", id="a line break"),
    ],
)
def test_the_person_goes_back_to_the_page_they_were_on_if_that_is_safe_and_exists(
    german: Flask, client: FlaskClient, db_session: Session, sent: str | None, goes_to: str
) -> None:
    signed_in(client, db_session)
    fields = {} if sent is None else {"next": sent}
    response = choose(client, "de_CH", **fields)
    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.endswith(goes_to) and "evil" not in location and "\n" not in location


def test_a_language_that_is_not_offered_is_refused_under_the_menu_and_nothing_changes(
    german: Flask, client: FlaskClient, db_session: Session
) -> None:
    user = signed_in(client, db_session, locale="en")
    forget_the_language()
    page = html(client.post("/profile/language", data={"locale": "fr_CH"}, follow_redirects=True))
    assert UNKNOWN in page
    db_session.refresh(user)
    assert user.locale == "en" and audit_rows(db_session, "user.profile_changed") == []


def test_the_refusal_is_translated_when_it_is_shown(
    german: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_in(client, db_session)
    monkeypatch.setattr("app.i18n._translations", lambda: Marked())
    page = html(client.post("/profile/language", data={"locale": "fr_CH"}, follow_redirects=True))
    assert f"[xx] {UNKNOWN}" in page


# ------------------------------------------------------------------------------ the menu


def test_the_menu_has_no_language_group_while_only_one_language_is_offered(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "LANGUAGES", ["en"])
    signed_in(client, db_session)
    items = menu(html(get(client, "/assessments/")))
    assert 'name="locale"' not in items and "Language" not in items


def test_the_menu_offers_each_language_by_name_and_marks_the_one_in_use(
    german: Flask, client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session)
    items = menu(html(get(client, "/assessments/?x=1")))

    assert "Language" in items
    assert 'name="next" value="/assessments/?x=1"' in items  # to come back to this page
    buttons = re.findall(r'<button [^>]*name="locale"[^>]*>.*?</button>', items, re.S)
    assert [re.search(r'value="([^"]+)"', b).group(1) for b in buttons] == OFFERED  # type: ignore[union-attr]
    assert [re.sub(r"<[^>]+>|\s+", "", b) for b in buttons] == ["English", "Deutsch"]
    assert items.count('aria-current="true"') == 1 and 'value="en" lang="en" aria-current' in items
    assert 'lang="de-CH"' in items  # the name of a language is read in that language


def test_the_menu_speaks_the_language_it_offers_to_leave(
    german: Flask, client: FlaskClient, db_session: Session
) -> None:
    signed_in(client, db_session, locale="de_CH")
    items = menu(html(get(client, "/assessments/")))
    assert "Sprache" in items and "Profil" in items and "Passwort" in items
    assert 'value="de_CH" lang="de-CH" aria-current' in items


# ------------------------------------------------------------------------------ English on demand


def test_english_is_english_inside_the_block_and_gives_the_language_back(german: Flask) -> None:
    forget_the_language()
    with german.test_request_context("/", headers={"Accept-Language": "de-CH"}):
        german.preprocess_request()
        assert gettext("Profile") == "Profil"
        with english():
            assert gettext("Profile") == "Profile"
            with english():  # blocks nest
                assert gettext("Profile") == "Profile"
            assert gettext("Profile") == "Profile"
        assert gettext("Profile") == "Profil"
    forget_the_language()


def test_english_gives_the_language_back_when_the_block_fails(german: Flask) -> None:
    forget_the_language()
    with german.test_request_context("/", headers={"Accept-Language": "de-CH"}):
        german.preprocess_request()
        with pytest.raises(RuntimeError), english():
            raise RuntimeError("the export failed")
        assert gettext("Profile") == "Profil"
    forget_the_language()


def test_english_outside_a_request_changes_nothing() -> None:
    with english():
        assert gettext("Profile") == "Profile"
