import json
import base64
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager
from password_manager.portable_backup import export_backup, import_backup
from utils.key_derivation import derive_index_key, derive_key_from_password


SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path):
    seed_key = derive_key_from_password(PASSWORD)
    seed_mgr = EncryptionManager(seed_key, tmp)
    seed_mgr.encrypt_parent_seed(SEED)

    index_key = derive_index_key(SEED)
    enc_mgr = EncryptionManager(index_key, tmp)
    vault = Vault(enc_mgr, tmp)
    cfg = ConfigManager(vault, tmp)
    backup = BackupManager(tmp, cfg)
    return vault, backup


def test_round_trip(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        data = {"pw": 1}
        vault.save_index(data)

        path = export_backup(vault, backup, parent_seed=SEED)
        assert path.exists()

        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == data["pw"]


from cryptography.fernet import InvalidToken


def test_corruption_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        content = json.loads(path.read_text())
        payload = base64.b64decode(content["payload"])
        payload = b"x" + payload[1:]
        content["payload"] = base64.b64encode(payload).decode()
        path.write_text(json.dumps(content))

        with pytest.raises(InvalidToken):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_import_over_existing(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"v": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        vault.save_index({"v": 2})
        import_backup(vault, backup, path, parent_seed=SEED)
        loaded = vault.load_index()
        assert loaded["v"] == 1


def test_checksum_mismatch_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        wrapper = json.loads(path.read_text())
        payload = base64.b64decode(wrapper["payload"])
        key = derive_index_key(SEED)
        enc_mgr = EncryptionManager(key, tmp)
        data = json.loads(enc_mgr.decrypt_data(payload).decode())
        data["a"] = 2
        mod_canon = json.dumps(data, sort_keys=True, separators=(",", ":"))
        new_payload = enc_mgr.encrypt_data(mod_canon.encode())
        wrapper["payload"] = base64.b64encode(new_payload).decode()
        path.write_text(json.dumps(wrapper))

        with pytest.raises(ValueError):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_export_import_seed_encrypted_with_different_key(monkeypatch):
    """Ensure backup round trip works when seed is encrypted with another key."""
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"v": 123})

        path = export_backup(vault, backup, parent_seed=SEED)
        vault.save_index({"v": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["v"] == 123
