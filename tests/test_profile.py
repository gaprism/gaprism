"""The initials in the avatar of the account menu."""

import pytest

from app.service.profile import initials


@pytest.mark.parametrize(
    ("who", "expected"),
    [
        ("anna.meier@example.org", "AM"),
        ("anna_meier-jones@example.org", "AM"),  # the first two words
        ("anna+work@example.org", "AW"),
        ("stefan@example.org", "S"),
        ("a@example.org", "A"),
        ("émile.dupont@example.org", "ÉD"),
        ("émile.dupont@example.org", "ÉD"),  # the accent typed as a separate mark
        ("_x@example.org", "X"),
        ("42.anna@example.org", "A"),  # digits are not initials
        ("12345@example.org", ""),
        ("山田.太郎@example.org", "山太"),
        ("ßeta@example.org", "S"),  # one capital per word, whatever the letter becomes
        ("Anna Meier", "AM"),  # a name works as well as an address
        ("", ""),
        ("@example.org", ""),
    ],
)
def test_the_initials_of_a_name_or_an_address(who: str, expected: str) -> None:
    assert initials(who) == expected
