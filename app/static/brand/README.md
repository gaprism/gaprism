# Gaprism logo and icons

These files come from the Gaprism logo kit, direction C (version 1, 30 October 2026). Use them as
they are: do not recolour, stretch, rotate, outline or redraw them, do not change the tail of the g,
and do not replace the lettering with typed text.

| File | Where the application uses it |
|---|---|
| `gaprism-logo-horizontal-color.svg` | The sidebar while it is open (160 px wide). |
| `gaprism-symbol-color.svg` | The sidebar as a rail, and the top bar on a phone (32 px). |
| `favicon.svg`, `favicon.ico` | The browser tab and bookmarks. |
| `apple-touch-icon.png` | The icon of a bookmark on an Apple home screen (180 px). |

The symbol is Indigo (`#4F46E5`) and the lettering Graphite (`#172033`), on white or Paper. The kit
asks for at least 160 px for the horizontal logo and 24 px for the symbol, and for a clear space of
one stem of the g (a fifth of the symbol's height) on every side. The lettering is IBM Plex Sans
converted to outlines, so no font is needed (its licence is in
[../licenses/ibm-plex-sans.txt](../licenses/ibm-plex-sans.txt)).

The vector files are plain paths and the others are bitmaps: nothing in them runs or loads anything,
and `tests/ui/test_brand_assets.py` keeps it so. `uv run python scripts/styleguide.py` shows every
file here with its sizes.

The name and the logo are not covered by the Apache licence: see
[TRADEMARK.md](../../../TRADEMARK.md).
