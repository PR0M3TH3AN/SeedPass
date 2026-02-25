"""Compat module providing :mod:`imghdr` for Python 3.13+.

This is a copy of Python 3.12's :mod:`imghdr` module which was removed in
Python 3.13. It is used by the ``pgpy`` dependency when deriving PGP keys.
"""

from __future__ import annotations

from os import PathLike
import warnings

__all__ = ["what"]

warnings.warn(
    "'imghdr' is deprecated and will be removed in Python 3.13",
    DeprecationWarning,
    stacklevel=2,
)

# -------------------------
# Recognize image headers
# -------------------------


def what(file, h=None):
    """Return the type of image contained in a file or byte stream."""
    f = None
    try:
        if h is None:
            if isinstance(file, (str, PathLike)):
                f = open(file, "rb")
                h = f.read(32)
            else:
                location = file.tell()
                h = file.read(32)
                file.seek(location)
        for tf in tests:
            res = tf(h, f)
            if res:
                return res
    finally:
        if f:
            f.close()
    return None


# ---------------------------------
# Subroutines per image file type
# ---------------------------------

tests: list = []


def test_jpeg(h, f):
    """Test for JPEG data with JFIF or Exif markers; and raw JPEG."""
    if h[6:10] in (b"JFIF", b"Exif"):
        return "jpeg"
    elif h[:4] == b"\xff\xd8\xff\xdb":
        return "jpeg"


tests.append(test_jpeg)


def test_png(h, f):
    """Verify if the image is a PNG."""
    if h.startswith(b"\211PNG\r\n\032\n"):
        return "png"


tests.append(test_png)


def test_gif(h, f):
    """Verify if the image is a GIF ('87 or '89 variants)."""
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"


tests.append(test_gif)


def test_tiff(h, f):
    """Verify if the image is a TIFF (Motorola or Intel)."""
    if h[:2] in (b"MM", b"II"):
        return "tiff"


tests.append(test_tiff)


def test_rgb(h, f):
    """Test for the SGI image library."""
    if h.startswith(b"\001\332"):
        return "rgb"


tests.append(test_rgb)


def test_pbm(h, f):
    """Verify if the image is a PBM."""
    if len(h) >= 3 and h[0] == ord(b"P") and h[1] in b"14" and h[2] in b" \t\n\r":
        return "pbm"


tests.append(test_pbm)


def test_pgm(h, f):
    """Verify if the image is a PGM."""
    if len(h) >= 3 and h[0] == ord(b"P") and h[1] in b"25" and h[2] in b" \t\n\r":
        return "pgm"


tests.append(test_pgm)


def test_ppm(h, f):
    """Verify if the image is a PPM."""
    if len(h) >= 3 and h[0] == ord(b"P") and h[1] in b"36" and h[2] in b" \t\n\r":
        return "ppm"


tests.append(test_ppm)


def test_rast(h, f):
    """Test for the Sun raster file."""
    if h.startswith(b"\x59\xa6\x6a\x95"):
        return "rast"


tests.append(test_rast)


def test_xbm(h, f):
    """Verify if the image is a X bitmap."""
    if h.startswith(b"#define "):
        return "xbm"


tests.append(test_xbm)


def test_bmp(h, f):
    """Verify if the image is a BMP file."""
    if h.startswith(b"BM"):
        return "bmp"


tests.append(test_bmp)


def test_webp(h, f):
    """Verify if the image is a WebP."""
    if h.startswith(b"RIFF") and h[8:12] == b"WEBP":
        return "webp"


tests.append(test_webp)


def test_exr(h, f):
    """Verify if the image is an OpenEXR file."""
    if h.startswith(b"\x76\x2f\x31\x01"):
        return "exr"


tests.append(test_exr)
