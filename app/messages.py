"""The marker for a sentence that is translated where it is shown, not where it is written.

``N_("Too many.")`` returns its argument unchanged. What it does is tell the extraction
(scripts/translations.py) that the sentence belongs in the catalogue. A sentence that is kept in a
constant, in a table or in something that travels (an error, a validator, a setting) is marked where
it is written, and looked up with ``_()`` where it is shown. docs/translation.md says more.

This module imports nothing, so that the configuration, the rules and the services can all use it.
"""


def N_(message: str) -> str:  # noqa: N802 - the name is the gettext convention
    return message
