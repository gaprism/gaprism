"""Compile checked-in gettext catalogs without reaching external services."""

from pathlib import Path

from babel.messages.mofile import write_mo
from babel.messages.pofile import read_po

for source in Path("app/translations").glob("*/LC_MESSAGES/messages.po"):
    with source.open("rb") as stream:
        catalog = read_po(stream)
    errors = list(catalog.check())
    if errors:
        raise ValueError(errors)
    with source.with_suffix(".mo").open("wb") as stream:
        write_mo(stream, catalog)
    print(f"Compiled {source}")
