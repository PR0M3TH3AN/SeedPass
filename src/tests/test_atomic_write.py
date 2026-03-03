import json
import pytest
from multiprocessing import Process
from pathlib import Path

from utils.atomic_write import atomic_write


def _writer(path: Path, content: dict, loops: int) -> None:
    for _ in range(loops):
        atomic_write(path, lambda f: json.dump(content, f), mode="w")


def test_atomic_write_concurrent(tmp_path: Path) -> None:
    """Concurrent writers should not leave partial files."""

    file_path = tmp_path / "data.json"
    contents = [{"proc": i} for i in range(5)]

    procs = [
        Process(target=_writer, args=(file_path, content, 50)) for content in contents
    ]

    for p in procs:
        p.start()
    for p in procs:
        p.join()

    final_text = file_path.read_text()
    final_obj = json.loads(final_text)
    assert final_obj in contents


def test_atomic_write_cleanup_on_failure(tmp_path: Path) -> None:
    """Temporary file should be cleaned up if write fails."""
    dest_path = tmp_path / "dest.txt"

    # Ensure directory is empty initially
    assert list(tmp_path.iterdir()) == []

    def failing_writer(f) -> None:
        # Verify temp file exists while writing
        # There should be exactly one file in the dir now
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        f.write("partial data")
        raise RuntimeError("Write failed")

    with pytest.raises(RuntimeError, match="Write failed"):
        atomic_write(dest_path, failing_writer)

    # Verify directory is empty again (temp file deleted)
    assert list(tmp_path.iterdir()) == []

    # Verify destination file was NOT created
    assert not dest_path.exists()


def test_atomic_write_preserves_existing_on_failure(tmp_path: Path) -> None:
    """Existing file should not be overwritten if write fails."""
    dest_path = tmp_path / "existing.txt"
    dest_path.write_text("original content")

    # There should be 1 file initially
    assert len(list(tmp_path.iterdir())) == 1

    def failing_writer(f) -> None:
        # There should be 2 files now (original + temp)
        assert len(list(tmp_path.iterdir())) == 2
        raise RuntimeError("Write failed")

    with pytest.raises(RuntimeError):
        atomic_write(dest_path, failing_writer)

    # Should revert to 1 file
    assert len(list(tmp_path.iterdir())) == 1
    assert dest_path.read_text() == "original content"


def test_atomic_write_permissions(tmp_path: Path) -> None:
    """File permissions should be set to 0o600 (owner read/write only)."""
    import stat

    test_file = tmp_path / "permissions.txt"

    def write_op(f):
        f.write("content")

    atomic_write(test_file, write_op)

    st = test_file.stat()
    mode = stat.S_IMODE(st.st_mode)
    assert mode == 0o600
