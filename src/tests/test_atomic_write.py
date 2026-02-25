import json
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
