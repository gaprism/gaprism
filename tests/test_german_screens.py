"""The German screens ask for no sentence that the catalogue lacks.

tests/test_translations.py proves that every sentence the source writes is translated. It cannot see
a sentence that is looked up through a variable (``_(label)``) and was never written down with
``N_``: such a sentence is simply not in the catalogue and stays English on a German screen. This
test opens the screens with the real catalogue, as a browser that asks for German, and counts every
sentence that gettext was asked for and the catalogue lacks.

The two words it does not hold against the catalogue are the names of Flask-Security's second-factor
methods: its templates compare them as text, so they are never translated (see docs/translation.md).
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field

import pytest
from babel.support import Translations
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.i18n as i18n
from app.models import Host, Role, User
from app.service import users as user_service
from tests.helpers import login_as
from tests.test_languages import forget_the_language
from tests.test_summary import evaluated

NOT_TRANSLATED_ON_PURPOSE = {"authenticator", "none"}


@dataclass
class Looked:
    """What was asked of the catalogue: how often, and the sentences it did not have."""

    asked: int = 0
    lacking: collections.Counter[str] = field(default_factory=collections.Counter)


class Recorder:
    """A catalogue that counts what it was asked for and does not have."""

    def __init__(self, inner: Translations, looked: Looked) -> None:
        self.inner, self.looked = inner, looked

    def gettext(self, message: str) -> str:
        self.looked.asked += 1
        if message and message not in self.inner._catalog:  # type: ignore[attr-defined]
            self.looked.lacking[message] += 1
        return self.inner.gettext(message)

    def ngettext(self, singular: str, plural: str, n: int) -> str:
        self.looked.asked += 1
        if (singular, 0) not in self.inner._catalog:  # type: ignore[attr-defined]
            self.looked.lacking[singular] += 1
        return self.inner.ngettext(singular, plural, n)


@pytest.fixture
def looked(monkeypatch: pytest.MonkeyPatch) -> Looked:
    found = Looked()
    original = i18n._translations

    def recording() -> object:
        catalogue = original()
        return Recorder(catalogue, found) if isinstance(catalogue, Translations) else catalogue

    monkeypatch.setattr("app.i18n._translations", recording)
    return found


def test_the_screens_ask_for_no_sentence_that_the_catalogue_lacks(
    client: FlaskClient, db_session: Session, looked: Looked
) -> None:
    scan, _rows = evaluated(db_session, "vendor.example")
    owner = db_session.get(User, scan.requested_by)
    assert owner is not None
    role = db_session.scalar(select(Role).where(Role.name == user_service.ADMIN_ROLE))
    owner.roles.append(role or Role(name=user_service.ADMIN_ROLE))
    owner.name = "Anna Muster"
    db_session.commit()
    base = f"/assessments/{scan.assessment_id}"
    paths = [
        "/assessments/",
        "/assessments/new",
        base,
        f"{base}/findings",
        f"{base}/domain",
        f"{base}/scans",
        f"{base}/compare",
        f"{base}/report",
        f"{base}/delete",
        "/accounts/",
        "/audit/",
        "/profile/",
        "/auth/change-password",
        "/auth/tf-setup",
        "/no-such-page",
    ]
    hosts = db_session.scalars(select(Host).where(Host.scan_id == scan.id)).all()
    assert len(hosts) >= 3
    paths += [f"{base}/hosts/{host.id}" for host in hosts]

    login_as(client, owner)
    for path in paths:
        forget_the_language()
        response = client.get(path, headers={"Accept-Language": "de-CH"}, follow_redirects=True)
        assert response.status_code in {200, 404}, path
        assert '<html lang="de-CH"' in response.get_data(as_text=True), path

    assert looked.asked > 1000, "the screens should have asked the catalogue for a great deal"
    unexpected = {
        text: count
        for text, count in looked.lacking.items()
        if text not in NOT_TRANSLATED_ON_PURPOSE
    }
    assert not unexpected, f"asked for, and not in the German catalogue: {unexpected}"
