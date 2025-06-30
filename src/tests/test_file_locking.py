import threading
from pathlib import Path

from utils.file_lock import exclusive_lock, shared_lock


def _writer(path: Path, content: str, exceptions: list[str]) -> None:
    try:
        with exclusive_lock(path):
            path.write_text(content)
    except Exception as e:  # pragma: no cover - just capture
        exceptions.append(repr(e))


def _reader(path: Path, results: list[str], exceptions: list[str]) -> None:
    try:
        with shared_lock(path):
            results.append(path.read_text())
    except Exception as e:  # pragma: no cover
        exceptions.append(repr(e))


def test_concurrent_shared_and_exclusive_lock(tmp_path: Path) -> None:
    file_path = tmp_path / "data.txt"
    file_path.write_text("init")

    exceptions: list[str] = []
    reads: list[str] = []
    for i in range(5):
        writer = threading.Thread(
            target=_writer, args=(file_path, f"value{i}", exceptions)
        )
        reader = threading.Thread(target=_reader, args=(file_path, reads, exceptions))

        writer.start()
        reader.start()
        writer.join()
        reader.join()

    assert not exceptions
    assert file_path.read_text() == "value4"
    assert len(reads) == 5
