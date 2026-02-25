import pytest
import io
from utils.imghdr_stub import what


def test_what_with_bytes_io_jpeg():
    """Test what() with a BytesIO object containing JPEG header."""
    # JPEG magic number: FF D8 FF E0 .. .. JFIF
    data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 20
    f = io.BytesIO(data)
    assert what(f) == "jpeg"


def test_what_with_bytes_io_png():
    """Test what() with a BytesIO object containing PNG header."""
    # PNG magic number: 89 50 4E 47 0D 0A 1A 0A
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    f = io.BytesIO(data)
    assert what(f) == "png"


def test_what_with_bytes_io_gif87a():
    """Test what() with a BytesIO object containing GIF87a header."""
    data = b"GIF87a" + b"\x00" * 26
    f = io.BytesIO(data)
    assert what(f) == "gif"


def test_what_with_bytes_io_gif89a():
    """Test what() with a BytesIO object containing GIF89a header."""
    data = b"GIF89a" + b"\x00" * 26
    f = io.BytesIO(data)
    assert what(f) == "gif"


def test_what_with_bytes_io_tiff_intel():
    """Test what() with a BytesIO object containing TIFF (Intel) header."""
    data = b"II" + b"\x00" * 30
    f = io.BytesIO(data)
    assert what(f) == "tiff"


def test_what_with_bytes_io_tiff_motorola():
    """Test what() with a BytesIO object containing TIFF (Motorola) header."""
    data = b"MM" + b"\x00" * 30
    f = io.BytesIO(data)
    assert what(f) == "tiff"


def test_what_with_bytes_io_rgb():
    """Test what() with a BytesIO object containing SGI RGB header."""
    data = b"\x01\xda" + b"\x00" * 30
    f = io.BytesIO(data)
    assert what(f) == "rgb"


def test_what_with_bytes_io_pbm():
    """Test what() with a BytesIO object containing PBM header."""
    # P1, P4 followed by whitespace
    data = b"P1 " + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "pbm"

    data = b"P4\n" + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "pbm"


def test_what_with_bytes_io_pgm():
    """Test what() with a BytesIO object containing PGM header."""
    # P2, P5 followed by whitespace
    data = b"P2\t" + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "pgm"

    data = b"P5\r" + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "pgm"


def test_what_with_bytes_io_ppm():
    """Test what() with a BytesIO object containing PPM header."""
    # P3, P6 followed by whitespace
    data = b"P3\n" + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "ppm"

    data = b"P6 " + b"\x00" * 29
    f = io.BytesIO(data)
    assert what(f) == "ppm"


def test_what_with_bytes_io_rast():
    """Test what() with a BytesIO object containing Sun Raster header."""
    data = b"\x59\xa6\x6a\x95" + b"\x00" * 28
    f = io.BytesIO(data)
    assert what(f) == "rast"


def test_what_with_bytes_io_xbm():
    """Test what() with a BytesIO object containing XBM header."""
    data = b"#define " + b"\x00" * 24
    f = io.BytesIO(data)
    assert what(f) == "xbm"


def test_what_with_bytes_io_bmp():
    """Test what() with a BytesIO object containing BMP header."""
    data = b"BM" + b"\x00" * 30
    f = io.BytesIO(data)
    assert what(f) == "bmp"


def test_what_with_bytes_io_webp():
    """Test what() with a BytesIO object containing WebP header."""
    # RIFF .... WEBP
    data = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 20
    f = io.BytesIO(data)
    assert what(f) == "webp"


def test_what_with_bytes_io_exr():
    """Test what() with a BytesIO object containing OpenEXR header."""
    data = b"\x76\x2f\x31\x01" + b"\x00" * 28
    f = io.BytesIO(data)
    assert what(f) == "exr"


def test_what_returns_none_for_unknown():
    """Test what() returns None for unknown file types."""
    f = io.BytesIO(b"\x00" * 32)
    assert what(f) is None


def test_what_with_file_path_str(tmp_path):
    """Test what() with a file path string."""
    p = tmp_path / "test_image.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 24)
    assert what(str(p)) == "png"


def test_what_with_path_object(tmp_path):
    """Test what() with a pathlib.Path object."""
    p = tmp_path / "test_image.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 20)
    assert what(p) == "jpeg"


def test_what_with_explicit_header():
    """Test what() with explicit header provided."""
    h = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    assert what(None, h) == "png"


def test_what_preserves_file_position():
    """Test that what() preserves the file position when passed a file object."""
    data = b"prefix" + b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    f = io.BytesIO(data)
    f.seek(6)  # Skip prefix
    original_pos = f.tell()

    res = what(f)

    assert res == "png"
    assert f.tell() == original_pos

def test_what_with_bytes_io_jpeg_exif():
    """Test what() with a BytesIO object containing JPEG Exif header."""
    # JPEG magic number: FF D8 FF E0 .. .. Exif
    data = b"\xff\xd8\xff\xe0\x00\x10Exif" + b"\x00" * 20
    f = io.BytesIO(data)
    assert what(f) == "jpeg"


def test_what_with_empty_file(tmp_path):
    """Test what() with an empty file."""
    p = tmp_path / "empty"
    p.touch()
    assert what(str(p)) is None


def test_what_with_empty_bytes_io():
    """Test what() with an empty BytesIO."""
    f = io.BytesIO(b"")
    assert what(f) is None


def test_what_with_short_file_bmp():
    """Test what() with a short file containing just the magic number."""
    f = io.BytesIO(b"BM")
    assert what(f) == "bmp"
