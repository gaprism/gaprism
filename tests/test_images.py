"""A picture a person uploads becomes one small square WebP that holds nothing but pixels.

What comes in is never kept as it is: it is decoded, cropped from the centre, scaled and written
again, so the metadata of the camera (where, when, with what) does not come along, and what is
stored is something this program made. The sentences a person is told are pinned here, as in the
other services: whole sentences, with the limits filled in last.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zlib

import pytest
from PIL import Image

from app.service import images
from app.service.users import UserAdminError

RED, BLUE = (255, 0, 0), (0, 0, 255)
TOO_LARGE = "The picture is larger than 2 MB. Choose a smaller one."
UNREADABLE = "The file could not be read as a JPEG, PNG or WebP picture. Choose another file."
TOO_MANY_PIXELS = "The picture has more than 16 million pixels. Reduce its size and try again."


def encoded(image: Image.Image, form: str, **options: object) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, form, **options)
    return buffer.getvalue()


def halves(
    size: tuple[int, int], first: tuple[int, int, int], second: tuple[int, int, int]
) -> Image.Image:
    """An image whose left half is one colour and whose right half is another."""
    picture = Image.new("RGB", size, first)
    picture.paste(second, (size[0] // 2, 0, size[0], size[1]))
    return picture


def noise(length: int) -> bytes:
    """Bytes that look random and are the same every time (a picture of them hardly compresses)."""
    blocks = (hashlib.sha256(str(number).encode()).digest() for number in range(length // 32 + 1))
    return b"".join(blocks)[:length]


def opened(data: bytes) -> Image.Image:
    result = Image.open(io.BytesIO(data))
    result.load()
    return result


def near(pixel: tuple[int, ...], colour: tuple[int, int, int], tolerance: int = 48) -> bool:
    return all(abs(a - b) <= tolerance for a, b in zip(pixel[:3], colour, strict=True))


def png_claiming(width: int, height: int) -> bytes:
    """A PNG that says it is width x height and holds no pixels: only a program that decodes it
    before it looks at the size would find that out."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00"))
        + chunk(b"IEND", b"")
    )


def test_the_limits_are_the_ones_the_sentences_name() -> None:
    assert images.MAX_PICTURE_BYTES == 2 * 1024 * 1024
    assert images.MAX_PIXELS == 16_000_000
    assert images.PICTURE_SIZE == 256
    assert images.PICTURE_TYPE == "image/webp"


@pytest.mark.parametrize("form", ["JPEG", "PNG", "WEBP"])
def test_each_accepted_format_becomes_a_square_webp(form: str) -> None:
    result = opened(images.make_avatar(encoded(halves((300, 200), RED, BLUE), form)))
    assert result.format == "WEBP" and result.size == (256, 256)


@pytest.mark.parametrize(
    ("mode", "form"),
    [("L", "PNG"), ("L", "JPEG"), ("P", "PNG"), ("CMYK", "JPEG"), ("RGBA", "PNG"), ("LA", "PNG")],
)
def test_the_colour_model_of_the_file_does_not_matter(mode: str, form: str) -> None:
    source = Image.new(mode, (64, 48), 128 if mode in {"L", "P"} else None)
    result = opened(images.make_avatar(encoded(source, form)))
    assert result.size == (256, 256)


def test_a_wide_picture_is_cropped_from_the_centre() -> None:
    wide = Image.new("RGB", (1000, 200), RED)
    wide.paste(BLUE, (400, 0, 600, 200))  # the middle 200 pixels are the square that is kept
    result = opened(images.make_avatar(encoded(wide, "PNG"))).convert("RGB")
    for corner in ((0, 0), (255, 0), (0, 255), (255, 255), (128, 128)):
        assert near(result.getpixel(corner), BLUE), corner


def test_a_tall_picture_is_cropped_from_the_centre_too() -> None:
    tall = Image.new("RGB", (200, 1000), RED)
    tall.paste(BLUE, (0, 400, 200, 600))
    result = opened(images.make_avatar(encoded(tall, "PNG"))).convert("RGB")
    assert near(result.getpixel((10, 10)), BLUE) and near(result.getpixel((245, 245)), BLUE)


def test_a_small_picture_is_scaled_up_to_the_same_size() -> None:
    result = opened(images.make_avatar(encoded(Image.new("RGB", (10, 10), RED), "PNG")))
    assert result.size == (256, 256) and near(result.convert("RGB").getpixel((128, 128)), RED)


def test_the_orientation_the_camera_wrote_is_applied() -> None:
    exif = Image.Exif()
    exif[0x0112] = 6  # "rotate 90 degrees clockwise to see it upright"
    upright = images.make_avatar(encoded(halves((100, 40), RED, BLUE), "JPEG", exif=exif))
    result = opened(upright).convert("RGB")
    assert near(result.getpixel((128, 20)), RED), "the left half became the top"
    assert near(result.getpixel((128, 236)), BLUE), "the right half became the bottom"


def test_what_the_camera_wrote_does_not_come_along() -> None:
    exif = Image.Exif()
    exif[0x010F] = "SECRET-MAKER"
    exif[0x0131] = "SECRET-SOFTWARE"
    data = encoded(
        halves((64, 64), RED, BLUE),
        "JPEG",
        exif=exif,
        comment=b"SECRET-COMMENT",
        icc_profile=b"SECRET-PROFILE",  # a colour profile is metadata too
    )
    for marker in (b"SECRET-MAKER", b"SECRET-COMMENT", b"SECRET-PROFILE"):
        assert marker in data  # the input does have them

    result = images.make_avatar(data)
    assert b"SECRET" not in result
    picture = opened(result)
    assert len(picture.getexif()) == 0
    assert not {"exif", "icc_profile", "xmp", "comment"} & set(picture.info)


def test_transparency_is_kept_and_a_solid_picture_gets_no_alpha_channel() -> None:
    see_through = Image.new("RGBA", (64, 64), (255, 0, 0, 255))
    see_through.paste((0, 0, 0, 0), (0, 0, 32, 64))
    result = opened(images.make_avatar(encoded(see_through, "PNG")))
    assert result.mode == "RGBA"
    assert result.getpixel((10, 128))[3] == 0 and result.getpixel((245, 128))[3] == 255

    assert opened(images.make_avatar(encoded(Image.new("RGB", (64, 64), RED), "PNG"))).mode == "RGB"


def test_an_animated_picture_keeps_its_first_frame() -> None:
    first, second = Image.new("RGB", (64, 64), RED), Image.new("RGB", (64, 64), BLUE)
    moving = encoded(
        first, "WEBP", save_all=True, append_images=[second], duration=100, lossless=True
    )
    if getattr(Image.open(io.BytesIO(moving)), "n_frames", 1) != 2:
        pytest.skip("this Pillow cannot write an animated WebP")

    result = opened(images.make_avatar(moving))
    assert getattr(result, "n_frames", 1) == 1
    assert near(result.convert("RGB").getpixel((128, 128)), RED)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(encoded(Image.new("RGB", (8, 8)), "GIF"), id="gif"),
        pytest.param(encoded(Image.new("RGB", (8, 8)), "BMP"), id="bmp"),
        pytest.param(encoded(Image.new("RGB", (8, 8)), "TIFF"), id="tiff"),
        pytest.param(
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>', id="svg"
        ),
        pytest.param(b"<html><script>alert(1)</script></html>", id="html"),
        pytest.param(bytes(range(256)) * 8, id="noise"),
        pytest.param(b"", id="empty"),
        pytest.param(b"\x89PNG\r\n\x1a\n" + b"not a chunk", id="png-header-only"),
        pytest.param(
            encoded(
                Image.frombytes("RGB", (120, 120), noise(120 * 120 * 3)),
                "JPEG",
            )[:5000],
            id="jpeg-cut-short",
        ),
    ],
)
def test_a_file_that_is_not_a_usable_picture_is_refused_in_one_sentence(data: bytes) -> None:
    with pytest.raises(UserAdminError) as refused:
        images.make_avatar(data)
    assert (refused.value.message, refused.value.params) == (UNREADABLE, {})
    assert str(refused.value) == UNREADABLE


def test_more_than_two_megabytes_is_refused_before_anything_is_decoded() -> None:
    with pytest.raises(UserAdminError) as refused:
        images.make_avatar(b"\x00" * (images.MAX_PICTURE_BYTES + 1))
    assert refused.value.message == "The picture is larger than %(max)d MB. Choose a smaller one."
    assert refused.value.params == {"max": 2}
    assert str(refused.value) == TOO_LARGE


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(png_claiming(5000, 5000), id="25 million pixels, as the header says"),
        pytest.param(png_claiming(4001, 4000), id="one column over the limit"),
        pytest.param(png_claiming(20000, 20000), id="a decompression bomb"),
    ],
)
def test_a_picture_with_too_many_pixels_is_refused_from_its_header(data: bytes) -> None:
    """These files hold no pixels at all: decoding them would give "unreadable", so getting the
    sentence about the size shows that the size was looked at first."""
    with pytest.raises(UserAdminError) as refused:
        images.make_avatar(data)
    assert refused.value.message == (
        "The picture has more than %(max)d million pixels. Reduce its size and try again."
    )
    assert refused.value.params == {"max": 16}
    assert str(refused.value) == TOO_MANY_PIXELS


def test_exactly_the_limit_is_still_accepted() -> None:
    sixteen_million = Image.new("L", (4000, 4000), 90)
    assert opened(images.make_avatar(encoded(sixteen_million, "PNG"))).size == (256, 256)
