from pathlib import Path

from seedpass.release_integrity import (
    generate_checksums,
    parse_checksum_line,
    verify_checksums,
)


def test_generate_checksums_sorts_entries(tmp_path: Path):
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")

    lines = generate_checksums([tmp_path], base_dir=tmp_path)

    assert len(lines) == 2
    assert lines[0].endswith("  a.txt")
    assert lines[1].endswith("  b.txt")


def test_parse_checksum_line_rejects_invalid_digest():
    bad_line = "not-a-sha  dist/file.whl"
    try:
        parse_checksum_line(bad_line)
    except ValueError as exc:
        assert "Invalid SHA-256 digest" in str(exc)
    else:
        raise AssertionError("Expected parse_checksum_line to fail")


def test_verify_checksums_success(tmp_path: Path):
    artifact = tmp_path / "file.bin"
    artifact.write_bytes(b"seedpass")
    checksum_lines = generate_checksums([artifact], base_dir=tmp_path)
    checksum_file = tmp_path / "SHA256SUMS"
    checksum_file.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    ok, failures = verify_checksums(checksum_file, base_dir=tmp_path)

    assert ok is True
    assert failures == []


def test_verify_checksums_detects_mismatch(tmp_path: Path):
    artifact = tmp_path / "file.bin"
    artifact.write_bytes(b"seedpass")
    checksum_lines = generate_checksums([artifact], base_dir=tmp_path)
    checksum_file = tmp_path / "SHA256SUMS"
    checksum_file.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    artifact.write_bytes(b"tampered")

    ok, failures = verify_checksums(checksum_file, base_dir=tmp_path)

    assert ok is False
    assert failures
    assert "checksum mismatch" in failures[0]
