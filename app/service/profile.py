"""What the interface shows about the person who is signed in."""

import re
import unicodedata

_LETTERS = re.compile(r"[^\W\d_]+")  # runs of letters: no digits, no underscore


def initials(who: str) -> str:
    """The capitals of an avatar: the first letter of each of the first two words.

    ``who`` is a name or an e-mail address; of an address only the part before the ``@``
    counts, so ``anna.meier@example.org`` gives ``AM``. Digits and punctuation are not
    initials, and a text without a letter gives an empty string.
    """
    words = _LETTERS.findall(unicodedata.normalize("NFC", who.partition("@")[0]))
    return "".join(word[0].upper()[0] for word in words[:2])
