import sys
from pathlib import Path
from multiprocessing import Process, Queue
from cryptography.fernet import Fernet
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.backup import BackupManager


def _writer(key: bytes, dir_path: Path, loops: int, out: Queue) -> None:
    try:
        enc = EncryptionManager(key, dir_path)
        vault = Vault(enc, dir_path)
        for _ in range(loops):
            data = vault.load_index()
            data["counter"] = data.get("counter", 0) + 1
            vault.save_index(data)
    except Exception as e:  # pragma: no cover - capture for assertion
        out.put(repr(e))


def _reader(key: bytes, dir_path: Path, loops: int, out: Queue) -> None:
    try:
        enc = EncryptionManager(key, dir_path)
        vault = Vault(enc, dir_path)
        for _ in range(loops):
            vault.load_index()
    except Exception as e:  # pragma: no cover - capture
        out.put(repr(e))


def _backup(dir_path: Path, loops: int, out: Queue) -> None:
    try:
        bm = BackupManager(dir_path)
        for _ in range(loops):
            bm.create_backup()
    except Exception as e:  # pragma: no cover - capture
        out.put(repr(e))


@pytest.mark.parametrize("loops", [5, pytest.param(20, marks=pytest.mark.stress)])
@pytest.mark.parametrize("_", range(3))
def test_concurrency_stress(tmp_path: Path, loops: int, _):
    key = Fernet.generate_key()
    enc = EncryptionManager(key, tmp_path)
    Vault(enc, tmp_path).save_index({"counter": 0})

    q: Queue = Queue()
    procs = [
        Process(target=_writer, args=(key, tmp_path, loops, q)),
        Process(target=_writer, args=(key, tmp_path, loops, q)),
        Process(target=_reader, args=(key, tmp_path, loops, q)),
        Process(target=_reader, args=(key, tmp_path, loops, q)),
        Process(target=_backup, args=(tmp_path, loops, q)),
    ]

    for p in procs:
        p.start()
    for p in procs:
        p.join()

    errors = []
    while not q.empty():
        errors.append(q.get())

    assert not errors

    vault = Vault(EncryptionManager(key, tmp_path), tmp_path)
    assert isinstance(vault.load_index(), dict)
