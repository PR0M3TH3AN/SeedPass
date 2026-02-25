import sys
from pathlib import Path
from multiprocessing import Process, Queue
import pytest
from helpers import TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from utils.key_derivation import derive_index_key, derive_key_from_password


def _writer(index_key: bytes, dir_path: Path, loops: int, out: Queue) -> None:
    try:
        enc = EncryptionManager(index_key, dir_path)
        vault = Vault(enc, dir_path)
        for _ in range(loops):
            data = vault.load_index()
            data["counter"] = data.get("counter", 0) + 1
            vault.save_index(data)
    except Exception as e:  # pragma: no cover - capture for assertion
        out.put(repr(e))


def _reader(index_key: bytes, dir_path: Path, loops: int, out: Queue) -> None:
    try:
        enc = EncryptionManager(index_key, dir_path)
        vault = Vault(enc, dir_path)
        for _ in range(loops):
            vault.load_index()
    except Exception as e:  # pragma: no cover - capture
        out.put(repr(e))


def _backup(index_key: bytes, dir_path: Path, loops: int, out: Queue) -> None:
    try:
        enc = EncryptionManager(index_key, dir_path)
        vault = Vault(enc, dir_path)
        cfg = ConfigManager(vault, dir_path)
        bm = BackupManager(dir_path, cfg)
        for _ in range(loops):
            bm.create_backup()
    except Exception as e:  # pragma: no cover - capture
        out.put(repr(e))


@pytest.mark.parametrize("loops", [5, pytest.param(20, marks=pytest.mark.stress)])
@pytest.mark.parametrize("_", range(3))
def test_concurrency_stress(tmp_path: Path, loops: int, _):
    index_key = derive_index_key(TEST_SEED)
    fp = generate_fingerprint(TEST_SEED)
    seed_key = derive_key_from_password(TEST_PASSWORD, fp)
    EncryptionManager(seed_key, tmp_path).encrypt_parent_seed(TEST_SEED)
    enc = EncryptionManager(index_key, tmp_path)
    Vault(enc, tmp_path).save_index({"counter": 0})

    q: Queue = Queue()
    procs = [
        Process(target=_writer, args=(index_key, tmp_path, loops, q)),
        Process(target=_writer, args=(index_key, tmp_path, loops, q)),
        Process(target=_reader, args=(index_key, tmp_path, loops, q)),
        Process(target=_reader, args=(index_key, tmp_path, loops, q)),
        Process(target=_backup, args=(index_key, tmp_path, loops, q)),
    ]

    for p in procs:
        p.start()
    for p in procs:
        p.join()

    errors = []
    while not q.empty():
        errors.append(q.get())

    assert not errors

    vault = Vault(EncryptionManager(index_key, tmp_path), tmp_path)
    assert isinstance(vault.load_index(), dict)
