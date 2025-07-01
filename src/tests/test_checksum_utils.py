import hashlib
from pathlib import Path

from utils import checksum


def test_calculate_checksum(tmp_path):
    file = tmp_path / "data.txt"
    content = "hello world"
    file.write_text(content)
    expected = hashlib.sha256(content.encode()).hexdigest()
    result = checksum.calculate_checksum(str(file))
    assert result == expected


def test_calculate_checksum_missing(tmp_path):
    missing = tmp_path / "missing.txt"
    assert checksum.calculate_checksum(str(missing)) is None


def test_verify_and_update(tmp_path):
    chk_file = tmp_path / "chk.txt"
    chk_file.write_text("abc")
    assert checksum.verify_checksum("abc", str(chk_file))
    assert not checksum.verify_checksum("def", str(chk_file))

    assert checksum.update_checksum("payload", str(chk_file))
    expected = hashlib.sha256("payload".encode()).hexdigest()
    assert chk_file.read_text() == expected


def test_initialize_checksum(tmp_path):
    data = tmp_path / "file.bin"
    data.write_text("payload")
    chk_file = tmp_path / "chk2.txt"
    assert checksum.initialize_checksum(str(data), str(chk_file))
    expected = hashlib.sha256("payload".encode()).hexdigest()
    assert chk_file.read_text() == expected
