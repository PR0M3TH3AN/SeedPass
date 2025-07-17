import json
import base64
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.portable_backup import export_backup, import_backup
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
    return vault, backup, cfg


def test_round_trip(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        data = {"pw": 1}
        vault.save_index(data)

        path = export_backup(vault, backup, parent_seed=SEED)
        assert path.exists()
        wrapper = json.loads(path.read_text())
        assert wrapper.get("cipher") == "aes-gcm"

        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == data["pw"]


from cryptography.fernet import InvalidToken


def test_corruption_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
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
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"v": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        vault.save_index({"v": 2})
        import_backup(vault, backup, path, parent_seed=SEED)
        loaded = vault.load_index()
        assert loaded["v"] == 1


def test_checksum_mismatch_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
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
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"v": 123})

        path = export_backup(vault, backup, parent_seed=SEED)
        vault.save_index({"v": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["v"] == 123


def test_export_creates_additional_backup_and_import(monkeypatch):
    with TemporaryDirectory() as td, TemporaryDirectory() as extra:
        tmp = Path(td)

        seed_key = derive_key_from_password(PASSWORD)
        seed_mgr = EncryptionManager(seed_key, tmp)
        seed_mgr.encrypt_parent_seed(SEED)

        index_key = derive_index_key(SEED)
        enc_mgr = EncryptionManager(index_key, tmp)
        vault = Vault(enc_mgr, tmp)
        cfg = ConfigManager(vault, tmp)
        cfg.set_additional_backup_path(extra)
        backup = BackupManager(tmp, cfg)

        vault.save_index({"v": 1})

        monkeypatch.setattr(time, "time", lambda: 4444)
        path = export_backup(vault, backup, parent_seed=SEED)

        extra_file = Path(extra) / f"{tmp.name}_{path.name}"
        assert extra_file.exists()

        vault.save_index({"v": 0})
        import_backup(vault, backup, extra_file, parent_seed=SEED)
        assert vault.load_index()["v"] == 1
