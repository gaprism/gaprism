"""What the interface shows about the person who is signed in, and what they may call themselves."""

from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import User
from app.models.user_image import UserImage
from app.service import audit as audit_service
from app.service import images
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


def picture_version(content: bytes) -> str:
    """The name of a stored picture: the start of its SHA-256. It is in the URL of the picture, so
    a browser keeps one for as long as the name stays the same, and asks again when it changes."""
    return hashlib.sha256(content).hexdigest()[:16]


def picture_of(session: Session, user_id: uuid.UUID) -> UserImage | None:
    """The stored picture of an account, or ``None`` when it has none."""
    return session.scalar(select(UserImage).where(UserImage.user_id == user_id))


def change_picture(session: Session, user: User, data: bytes) -> bool:
    """Give ``user`` the picture that ``data`` (an upload) is made into, see ``images``.

    What is stored replaces the old picture: there is one for each account. Returns whether
    anything changed (the same picture again does not). The audit log says that a picture was set,
    never what it shows. Raises ``UserAdminError`` for an upload that cannot be used; the account
    is untouched then. The caller commits.
    """
    content = images.make_avatar(data)
    version = picture_version(content)
    if user.picture_version == version:
        return False
    stored = picture_of(session, user.id)
    if stored is None:
        session.add(UserImage(user_id=user.id, content=content))
    else:
        stored.content = content
    user.picture_version = version
    session.flush()
    audit_service.record(
        session,
        "user.profile_changed",
        subject=str(user.id),
        details={"email": user.email, "picture": "set"},
    )
    return True


def remove_picture(session: Session, user: User) -> bool:
    """Take the picture of ``user`` away; its bytes are deleted, not hidden. Returns whether there
    was one. The caller commits."""
    stored = picture_of(session, user.id)
    if stored is None and user.picture_version is None:
        return False
    if stored is not None:
        session.delete(stored)
    user.picture_version = None
    session.flush()
    audit_service.record(
        session,
        "user.profile_changed",
        subject=str(user.id),
        details={"email": user.email, "picture": "removed"},
    )
    return True
