"""What a person calls themselves: the name is cleaned and bounded, and every change is audited
without the name in the entry.

The odd characters are written as ``\\N{NAME}`` on purpose: a text-direction mark or a zero-width
space typed into this file would be invisible to everybody who reads it."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.service import audit as audit_service
from app.service import profile as profile_service
from app.service.users import UserAdminError
from tests.helpers import audit_rows, create_user

# The sentences a person is told. Whole sentences, apart from the limit that is filled in last.
NAME_TOO_LONG = "The name has more than 100 characters. Shorten it."
NAME_CHARACTER = (
    "The name contains a character that cannot be shown, such as a text-direction mark. Remove it."
)
# Persian writes "mi-khaham" with a zero-width non-joiner between the words' parts.
PERSIAN = "\N{ARABIC LETTER FARSI YEH}\N{ZERO WIDTH NON-JOINER}\N{ARABIC LETTER KHAH}"


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("Anna Meier", "Anna Meier"),
        ("  Anna   Meier  ", "Anna Meier"),  # the edges go, a run of spaces becomes one
        ("Anna\N{NO-BREAK SPACE}Meier", "Anna Meier"),  # a no-break space is a space
        ("Anna\tMeier\n", "Anna Meier"),  # so are a tab and a line break
        (  # composed: the same name is the same text
            "Noe\N{COMBINING DIAERESIS}l",
            "No\N{LATIN SMALL LETTER E WITH DIAERESIS}l",
        ),
        (PERSIAN, PERSIAN),  # joiners that scripts need are kept
        ("a\N{ZERO WIDTH JOINER}b", "a\N{ZERO WIDTH JOINER}b"),
        ("A" * 100, "A" * 100),  # exactly the limit
        ("A" * 50 + " " * 20 + "B" * 49, "A" * 50 + " " + "B" * 49),  # the limit counts the result
        ("", None),
        ("   ", None),
        ("\n\t", None),
        (None, None),
    ],
)
def test_a_name_is_cleaned(raw: str | None, clean: str | None) -> None:
    assert profile_service.clean_name(raw) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "Anna\N{RIGHT-TO-LEFT OVERRIDE}Meier",  # reorders what comes after it
        "Anna\N{LEFT-TO-RIGHT ISOLATE}Meier\N{POP DIRECTIONAL ISOLATE}",
        "Anna\N{LEFT-TO-RIGHT MARK}Meier",
        "Anna\N{ZERO WIDTH SPACE}Meier",
        "Anna\N{ZERO WIDTH NO-BREAK SPACE}Meier",  # also the byte order mark
        "Anna\x00Meier",  # NUL: a database cannot hold it
        "Anna\x07",  # bell
        "Anna" + chr(0xE000),  # private use
    ],
)
def test_a_name_with_a_character_that_cannot_be_shown_is_refused(raw: str) -> None:
    with pytest.raises(UserAdminError) as refused:
        profile_service.clean_name(raw)
    assert (refused.value.message, refused.value.params) == (NAME_CHARACTER, {})
    assert str(refused.value) == NAME_CHARACTER  # the command line would print it as it stands


def test_a_name_over_the_limit_is_refused_and_the_limit_is_filled_in_last() -> None:
    assert profile_service.MAX_NAME_LENGTH == 100
    with pytest.raises(UserAdminError) as refused:
        profile_service.clean_name("A" * 101)
    assert refused.value.message == "The name has more than %(max)d characters. Shorten it."
    assert refused.value.params == {"max": 100}
    assert str(refused.value) == NAME_TOO_LONG


def test_a_name_is_stored_and_audited_without_the_name(db_session: Session) -> None:
    user = create_user(db_session)
    assert profile_service.change_name(db_session, user, "  Anna   Meier ") is True
    assert user.name == "Anna Meier"

    (event,) = audit_rows(db_session, "user.profile_changed")
    assert event.subject == str(user.id)
    assert event.details == {"email": user.email, "name": "set"}
    assert "Anna" not in f"{event.details} {event.subject}"  # Rule 9: what people type stays out


def test_the_same_name_again_changes_nothing_and_is_not_audited(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_name(db_session, user, "Anna Meier")
    assert profile_service.change_name(db_session, user, " Anna    Meier ") is False
    assert len(audit_rows(db_session, "user.profile_changed")) == 1


def test_a_name_can_be_taken_away(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_name(db_session, user, "Anna Meier")
    assert profile_service.change_name(db_session, user, "   ") is True
    assert user.name is None
    assert profile_service.change_name(db_session, user, "") is False  # nothing left to take
    cleared = audit_rows(db_session, "user.profile_changed")[-1]
    assert cleared.details == {"email": user.email, "name": "cleared"}


def test_a_refused_name_leaves_the_name_and_the_log_as_they_were(db_session: Session) -> None:
    user = create_user(db_session)
    profile_service.change_name(db_session, user, "Anna Meier")
    for refused in ("Anna\N{RIGHT-TO-LEFT OVERRIDE}", "B" * 101):
        with pytest.raises(UserAdminError):
            profile_service.change_name(db_session, user, refused)
    assert user.name == "Anna Meier"
    assert len(audit_rows(db_session, "user.profile_changed")) == 1


def test_the_change_has_words_on_the_audit_page() -> None:
    assert audit_service.action_label("user.profile_changed") == "Changed their own profile"
