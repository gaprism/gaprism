"""The application shell: sign-in gate, layouts, error pages and security headers."""

import re
import uuid

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.config import TestingConfig
from app.service.users import create_admin
from tests.helpers import create_assessment, create_user, login_as, make_app


def test_start_page_leads_to_the_assessments_list(client: FlaskClient) -> None:
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/assessments/")


def test_assessments_require_sign_in(client: FlaskClient) -> None:
    response = client.get("/assessments/")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_forged_identity_headers_and_legacy_sessions_do_not_authenticate(
    client: FlaskClient,
) -> None:
    forged = client.get(
        "/assessments/",
        headers={"X-Test-Actor-Id": str(uuid.uuid4()), "X-Test-Workspace-Id": str(uuid.uuid4())},
    )
    assert forged.status_code == 302
    assert "/auth/login" in forged.headers["Location"]

    with client.session_transaction() as state:
        state["actor_user_id"] = str(uuid.uuid4())
        state["user_id"] = str(uuid.uuid4())
    assert client.get("/assessments/").status_code == 302


def test_login_page_renders_in_the_public_layout(client: FlaskClient) -> None:
    """Flask-Security's pages extend our layout (the old UI failed to render at all)."""
    response = client.get("/auth/login")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Gaprism" in page
    assert 'name="email"' in page and 'name="password"' in page
    assert "Sign out" not in page  # public layout has no account header
    assert "nav.js" not in page and "popovertarget" not in page  # nor a sidebar
    assert "account-menu" not in page
    assert "/static/css/app.css" in page and "/static/js/htmx.min.js" in page


def test_signed_in_user_sees_an_empty_assessments_page(
    client: FlaskClient, db_session: Session
) -> None:
    user = create_user(db_session, "analyst@example.org")
    login_as(client, user)

    response = client.get("/assessments/")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "No assessments yet" in page
    assert "analyst@example.org" in page
    assert "Sign out" in page
    assert "hx-headers=" in page and "X-CSRFToken" in page  # HTMX requests carry the CSRF token


def test_the_account_menu_takes_the_account_links_out_of_the_top_bar(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session, "anna.meier@example.org"))

    page = client.get("/assessments/").get_data(as_text=True)
    header = re.search(r"<header[^>]*>(.*?)</header>", page, re.S)
    assert header is not None
    bar = header.group(1)
    assert "Technical verification" not in page

    button = re.search(r'<button[^>]*popovertarget="account-menu"[^>]*>(.*?)</button>', bar, re.S)
    assert button is not None and 'aria-label="Account menu"' in button.group(0)
    assert '<span class="avatar" aria-hidden="true">AM</span>' in button.group(1)

    menu = re.search(r'<ul id="account-menu" popover[^>]*>(.*?)</ul>', bar, re.S)
    assert menu is not None
    items = menu.group(1)
    assert "Signed in as" in items and "anna.meier@example.org" in items
    assert "Administrator" not in items
    assert re.search(r'<a [^>]*href="[^"]*"[^>]*>Password</a>', items)
    assert re.search(r'<a [^>]*href="/auth/tf-setup"[^>]*>Two-factor</a>', items)
    sign_out = (
        r'<form action="/auth/logout" method="post">.*?name="csrf_token"'
        r'.*?type="submit">Sign out</button>'
    )
    assert re.search(sign_out, items, re.S)

    # Nothing of it is left in the bar itself.
    rest = bar.replace(menu.group(0), "")
    for text in ("Sign out", "Password", "Two-factor", "anna.meier@example.org"):
        assert text not in rest, text


def test_the_account_menu_says_when_the_account_is_an_administrator(
    client: FlaskClient, db_session: Session
) -> None:
    admin = create_admin(db_session, "boss@example.org", "Administrator-Pass-1")
    db_session.commit()
    login_as(client, admin)

    page = client.get("/assessments/").get_data(as_text=True)
    menu = re.search(r'<ul id="account-menu" popover[^>]*>(.*?)</ul>', page, re.S)
    assert menu is not None and "Administrator" in menu.group(1)
    assert '<span class="avatar" aria-hidden="true">B</span>' in page


def test_the_breadcrumb_is_in_the_top_bar_and_not_in_the_page(
    client: FlaskClient, db_session: Session
) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "vendor.example")
    login_as(client, user)

    page = client.get(f"/assessments/{assessment.id}/findings").get_data(as_text=True)
    bar = re.search(r"<header[^>]*>(.*?)</header>", page, re.S)
    main = re.search(r"<main[^>]*>(.*?)</main>", page, re.S)
    assert bar is not None and main is not None
    trail = re.search(r'<nav aria-label="Breadcrumb"[^>]*>(.*?)</nav>', bar.group(1), re.S)
    assert trail is not None
    assert 'href="/assessments/"' in trail.group(1) and "vendor.example" in trail.group(1)
    assert f'href="/assessments/{assessment.id}"' in trail.group(1)
    assert "Breadcrumb" not in main.group(1)

    # A page at the top level has no trail; the title of the page says where it is.
    assert "Breadcrumb" not in client.get("/assessments/").get_data(as_text=True)

    # Below 768 px the sidebar and its logo are gone: the bar carries the logo, linked home.
    assert re.search(r'<a href="/assessments/" class="topbar-brand[^"]*">', bar.group(1))


def test_the_navigation_is_a_sidebar_that_collapses_with_a_menu_button_on_narrow_screens(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session, "analyst@example.org"))

    page = client.get("/assessments/").get_data(as_text=True)
    head, body = page.split("<body", 1)
    # Not deferred: a collapsed sidebar has to be collapsed from the first paint.
    assert '<script src="/static/js/nav.js"></script>' in head

    match = re.search(r'<aside class="sidebar"[^>]*>(.*?)</aside>', body, re.S)
    assert match is not None
    sidebar = match.group(1)
    # The icon rail hides the words: each link keeps them for screen readers, and a tooltip.
    assert 'data-tip="Assessments"' in sidebar
    assert '<span class="nav-label">Assessments</span>' in sidebar
    assert 'id="primary-nav"' in sidebar
    button = re.search(r"<button[^>]*data-nav-toggle[^>]*>", sidebar)
    assert button is not None
    for attribute in (
        'aria-controls="primary-nav"',
        'aria-expanded="true"',
        'data-label-collapse="Collapse the navigation"',
        'data-label-expand="Expand the navigation"',
    ):
        assert attribute in button.group(0)

    # Below 768 px the sidebar is gone and the same links open from a menu button as a panel.
    assert 'popovertarget="nav-panel"' in body
    panel = re.search(r'<nav id="nav-panel" popover[^>]*>(.*?)</nav>', body, re.S)
    assert panel is not None
    assert "Assessments" in panel.group(1) and "nav-label" not in panel.group(1)
    assert "/audit/" not in sidebar + panel.group(1)  # administrators only


def test_administrators_find_their_links_in_the_sidebar_and_in_the_panel(
    client: FlaskClient, db_session: Session
) -> None:
    admin = create_admin(db_session, "boss@example.org", "Administrator-Pass-1")
    db_session.commit()
    login_as(client, admin)

    page = client.get("/assessments/").get_data(as_text=True)
    for path in ("/audit/", "/accounts/"):
        assert page.count(f'href="{path}"') == 2, path


def test_assessments_list_shows_only_what_the_user_may_open(
    client: FlaskClient, db_session: Session
) -> None:
    me = create_user(db_session)
    colleague = create_user(db_session)
    create_assessment(db_session, me, "mine.example", "private")
    create_assessment(db_session, colleague, "shared.example", "shared")
    create_assessment(db_session, colleague, "secret.example", "private")
    login_as(client, me)

    page = client.get("/assessments/").get_data(as_text=True)
    assert "mine.example" in page
    assert "shared.example" in page
    assert "secret.example" not in page
    assert "Shared" in page and "Private" in page  # the badges of the two visible assessments


def test_target_controlled_text_is_escaped(client: FlaskClient, db_session: Session) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user)
    assessment.label = '<script>alert("x")</script>'
    db_session.commit()
    login_as(client, user)

    page = client.get("/assessments/").get_data(as_text=True)
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page


def test_unknown_pages_render_a_generic_404(client: FlaskClient) -> None:
    response = client.get("/no-such-page")
    assert response.status_code == 404
    page = response.get_data(as_text=True)
    assert "Not found" in page
    assert "Traceback" not in page and "werkzeug" not in page.lower()


def test_security_headers_on_pages_errors_and_static_files(client: FlaskClient) -> None:
    for path in ("/healthz", "/no-such-page", "/auth/login"):
        headers = client.get(path).headers
        policy = headers["Content-Security-Policy"]
        assert "'unsafe-inline'" not in policy and "'unsafe-eval'" not in policy
        assert "frame-ancestors 'none'" in policy and "object-src 'none'" in policy
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Cache-Control"] == "no-store"
        assert "Strict-Transport-Security" not in headers  # only behind HTTPS in production

    static = client.get("/static/css/app.css")
    assert static.status_code == 200
    assert static.headers.get("Cache-Control") != "no-store"


def test_healthz_is_public_and_minimal(client: FlaskClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"status": "healthy", "env": "testing"}


def test_csrf_is_enforced_on_form_posts(database_url: str, schema_name: str) -> None:
    app = make_app(database_url, schema_name, WTF_CSRF_ENABLED=True)
    response = app.test_client().post(
        "/auth/login", data={"email": "a@example.org", "password": "x"}
    )
    assert response.status_code == 400


def test_administrators_see_every_assessment(client: FlaskClient, db_session: Session) -> None:
    admin = create_admin(db_session, "boss@example.org", "Administrator-Pass-1")
    db_session.commit()
    owner = create_user(db_session)
    create_assessment(db_session, owner, "private-of-someone-else.example", "private")
    login_as(client, admin)

    assert "private-of-someone-else.example" in client.get("/assessments/").get_data(as_text=True)


@pytest.mark.parametrize(("require", "expected"), [(False, False), (True, True)])
def test_require_mfa_controls_enrolment_but_keeps_mfa_available(
    require: bool, expected: bool
) -> None:
    """D3: MFA can always be used; REQUIRE_MFA only decides whether enrolment is forced."""
    from app import create_app

    class Config(TestingConfig):
        REQUIRE_MFA = require

    app: Flask = create_app(Config)
    assert app.config["SECURITY_TWO_FACTOR"] is True
    assert app.config["SECURITY_TWO_FACTOR_REQUIRED"] is expected
