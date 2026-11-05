"""Pictures: what a person uploads becomes one small square WebP that holds nothing but pixels.

The upload is never kept as it came. Its size in bytes, its format and its size in pixels are
looked at before it is decoded; then it is decoded, turned upright, cropped from the centre, scaled
and written again. What is stored is something this program made: no location, no camera, no
comment and no colour profile come along. A refusal is a ``UserAdminError`` with a sentence for the
person who chose the file.
"""

from __future__ import annotations

import io
import struct
import zlib

from PIL import Image, ImageOps

from app.messages import N_
from app.service.users import UserAdminError

MAX_PICTURE_BYTES = 2 * 1024 * 1024  # what is read at all
MAX_PIXELS = 16_000_000  # width x height, 4000 x 4000: a photo from any phone, nothing absurd
PICTURE_SIZE = 256  # pixels on a side; the avatars are shown at 96 and below
PICTURE_TYPE = "image/webp"
_FORMATS = ("JPEG", "PNG", "WEBP")  # not GIF, not SVG: what is not listed is never opened
_QUALITY = 85
_MEGABYTE = 1024 * 1024
_ALPHA_MODES = {"RGBA", "LA", "PA"}
_DECODE_ERRORS = (OSError, ValueError, SyntaxError, EOFError, struct.error, zlib.error)

PICTURE_TOO_LARGE = N_("The picture is larger than %(max)d MB. Choose a smaller one.")
PICTURE_UNREADABLE = N_(
    "The file could not be read as a JPEG, PNG or WebP picture. Choose another file."
)
PICTURE_TOO_MANY_PIXELS = N_(
    "The picture has more than %(max)d million pixels. Reduce its size and try again."
)


def make_avatar(data: bytes) -> bytes:
    """The picture as a ``PICTURE_SIZE`` square WebP (``PICTURE_TYPE``), or a refusal."""
    if len(data) > MAX_PICTURE_BYTES:
        raise UserAdminError(PICTURE_TOO_LARGE, max=MAX_PICTURE_BYTES // _MEGABYTE)
    try:
        source = Image.open(io.BytesIO(data), formats=_FORMATS)
    except Image.DecompressionBombError as exc:  # it says how big it is, and that is far too big
        raise UserAdminError(PICTURE_TOO_MANY_PIXELS, max=MAX_PIXELS // 1_000_000) from exc
    except _DECODE_ERRORS as exc:  # also "not an image" and "a format that is not listed"
        raise UserAdminError(PICTURE_UNREADABLE) from exc
    with source:
        if source.width * source.height > MAX_PIXELS:  # from the header: nothing is decoded yet
            raise UserAdminError(PICTURE_TOO_MANY_PIXELS, max=MAX_PIXELS // 1_000_000)
        try:
            return _square(source)
        except Image.DecompressionBombError as exc:
            raise UserAdminError(PICTURE_TOO_MANY_PIXELS, max=MAX_PIXELS // 1_000_000) from exc
        except _DECODE_ERRORS as exc:  # cut short, damaged, or not what its header says
            raise UserAdminError(PICTURE_UNREADABLE) from exc


def _square(source: Image.Image) -> bytes:
    keeps_alpha = source.mode in _ALPHA_MODES or "transparency" in source.info
    if source.format == "JPEG":  # decoded at a fraction of its size: a big photo costs little
        source.draft("RGB", (PICTURE_SIZE * 2, PICTURE_SIZE * 2))
    upright = ImageOps.exif_transpose(source)  # the first frame of an animated picture, upright
    picture = upright.convert("RGBA" if keeps_alpha else "RGB")
    picture = ImageOps.fit(picture, (PICTURE_SIZE, PICTURE_SIZE), method=Image.Resampling.LANCZOS)
    picture.info = {}  # convert and fit carry the upload's info along; none of it is written today
    stored = io.BytesIO()
    picture.save(stored, "WEBP", quality=_QUALITY)
    return stored.getvalue()
