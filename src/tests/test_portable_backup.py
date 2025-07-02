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
from password_manager.portable_backup import (
    PortableMode,
    export_backup,
    import_backup,
)
from utils.key_derivation import derive_index_key, EncryptionMode


SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path, mode: EncryptionMode = EncryptionMode.SEED_ONLY):
    index_key = derive_index_key(SEED, PASSWORD, mode)
    enc_mgr = EncryptionManager(index_key, tmp)
    enc_mgr.encrypt_parent_seed(SEED)
    vault = Vault(enc_mgr, tmp)
    backup = BackupManager(tmp)
    return vault, backup


def test_round_trip_across_modes(monkeypatch):
    for pmode in [
        PortableMode.SEED_ONLY,
        PortableMode.SEED_PLUS_PW,
        PortableMode.PW_ONLY,
    ]:
        with TemporaryDirectory() as td:
            tmp = Path(td)
            vault, backup = setup_vault(tmp)
            data = {"pw": 1}
            vault.save_index(data)

            monkeypatch.setattr(
                "password_manager.portable_backup.prompt_existing_password",
                lambda *_a, **_k: PASSWORD,
            )

            path = export_backup(vault, backup, pmode)
            assert path.exists()

            vault.save_index({"pw": 0})
            import_backup(vault, backup, path)
            assert vault.load_index() == data


def test_corruption_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 1})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(vault, backup, PortableMode.SEED_ONLY)

        content = json.loads(path.read_text())
        payload = base64.b64decode(content["payload"])
        payload = b"x" + payload[1:]
        content["payload"] = base64.b64encode(payload).decode()
        path.write_text(json.dumps(content))

        with pytest.raises(ValueError):
            import_backup(vault, backup, path)


def test_incorrect_credentials(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 2})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(vault, backup, PortableMode.SEED_PLUS_PW)

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: "wrong",
        )
        with pytest.raises(Exception):
            import_backup(vault, backup, path)


def test_import_over_existing(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"v": 1})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(vault, backup, PortableMode.SEED_ONLY)

        vault.save_index({"v": 2})
        import_backup(vault, backup, path)
        assert vault.load_index() == {"v": 1}
