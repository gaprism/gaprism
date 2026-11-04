"""What the interface shows about the person who is signed in, and what they may call themselves."""

from __future__ import annotations

import re
import unicodedata

from sqlalchemy.orm import Session

from app.models.auth import User
from app.service import audit as audit_service
from app.service.users import UserAdminError

MAX_NAME_LENGTH = 100
NAME_TOO_LONG = "The name has more than %(max)d characters. Shorten it."
NAME_CHARACTER = (
    "The name contains a character that cannot be shown, such as a text-direction mark. Remove it."
)

_LETTERS = re.compile(r"[^\W\d_]+")  # runs of letters: no digits, no underscore
_SPACES = re.compile(r"\s+")
_JOINERS = {"\N{ZERO WIDTH NON-JOINER}", "\N{ZERO WIDTH JOINER}"}  # scripts need them
_NOT_SHOWN = {"Cc", "Cf", "Cs", "Co"}  # control, format, surrogate and private-use characters


def initials(who: str) -> str:
    """The capitals of an avatar: the first letter of each of the first two words.

    ``who`` is a name or an e-mail address; of an address only the part before the ``@``
    counts, so ``anna.meier@example.org`` gives ``AM``. Digits and punctuation are not
    initials, and a text without a letter gives an empty string.
    """
    words = _LETTERS.findall(unicodedata.normalize("NFC", who.partition("@")[0]))
    return "".join(word[0].upper()[0] for word in words[:2])


def clean_name(raw: str | None) -> str | None:
    """A name as it is stored: composed, with its white space tidied, or ``None`` for no name.

    Every run of white space (a tab, a line break, a no-break space) becomes one space and the
    edges go. A control, format or private-use character is refused, because it is not shown or it
    changes how the text around it is shown (a text-direction mark reorders it); the joiners that
    some scripts need are kept. The limit counts what is left. Raises ``UserAdminError``.
    """
    if raw is None:
        return None
    text = _SPACES.sub(" ", unicodedata.normalize("NFC", raw)).strip()
    for character in text:
        if unicodedata.category(character) in _NOT_SHOWN and character not in _JOINERS:
            raise UserAdminError(NAME_CHARACTER)
    if len(text) > MAX_NAME_LENGTH:
        raise UserAdminError(NAME_TOO_LONG, max=MAX_NAME_LENGTH)
    return text or None


def change_name(session: Session, user: User, raw: str | None) -> bool:
    """Give ``user`` the name (a blank one takes it away). Returns whether anything changed.

    A change is written to the audit log: that a name was set or cleared, never the name. The
    caller commits.
    """
    name = clean_name(raw)
    if name == user.name:
        return False
    user.name = name
    session.flush()
    audit_service.record(
        session,
        "user.profile_changed",
        subject=str(user.id),
        details={"email": user.email, "name": "set" if name else "cleared"},
    )
    return True
