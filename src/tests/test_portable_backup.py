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
from utils.key_derivation import (
    derive_index_key,
    derive_key_from_password,
    EncryptionMode,
)


SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path, mode: EncryptionMode = EncryptionMode.SEED_ONLY):
    seed_key = derive_key_from_password(PASSWORD)
    seed_mgr = EncryptionManager(seed_key, tmp)
    seed_mgr.encrypt_parent_seed(SEED)

    index_key = derive_index_key(SEED, PASSWORD, mode)
    enc_mgr = EncryptionManager(index_key, tmp)
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

            path = export_backup(vault, backup, pmode, parent_seed=SEED)
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

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(vault, backup, PortableMode.SEED_ONLY, parent_seed=SEED)

        content = json.loads(path.read_text())
        payload = base64.b64decode(content["payload"])
        payload = b"x" + payload[1:]
        content["payload"] = base64.b64encode(payload).decode()
        path.write_text(json.dumps(content))

        with pytest.raises(InvalidToken):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_incorrect_credentials(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 2})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(
            vault,
            backup,
            PortableMode.SEED_PLUS_PW,
            parent_seed=SEED,
        )

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: "wrong",
        )
        with pytest.raises(Exception):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_import_over_existing(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"v": 1})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )
        path = export_backup(vault, backup, PortableMode.SEED_ONLY, parent_seed=SEED)

        vault.save_index({"v": 2})
        import_backup(vault, backup, path, parent_seed=SEED)
        loaded = vault.load_index()
        assert loaded["v"] == 1


def test_checksum_mismatch_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"a": 1})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )

        path = export_backup(
            vault,
            backup,
            PortableMode.SEED_ONLY,
            parent_seed=SEED,
        )

        wrapper = json.loads(path.read_text())
        payload = base64.b64decode(wrapper["payload"])
        key = derive_index_key(SEED, PASSWORD, EncryptionMode.SEED_ONLY)
        enc_mgr = EncryptionManager(key, tmp)
        data = json.loads(enc_mgr.decrypt_data(payload).decode())
        data["a"] = 2
        mod_canon = json.dumps(data, sort_keys=True, separators=(",", ":"))
        new_payload = enc_mgr.encrypt_data(mod_canon.encode())
        wrapper["payload"] = base64.b64encode(new_payload).decode()
        path.write_text(json.dumps(wrapper))

        with pytest.raises(ValueError):
            import_backup(vault, backup, path, parent_seed=SEED)


@pytest.mark.parametrize(
    "pmode",
    [PortableMode.SEED_ONLY, PortableMode.SEED_PLUS_PW],
)
def test_export_import_seed_encrypted_with_different_key(monkeypatch, pmode):
    """Ensure backup round trip works when seed is encrypted with another key."""
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup = setup_vault(tmp)
        vault.save_index({"v": 123})

        monkeypatch.setattr(
            "password_manager.portable_backup.prompt_existing_password",
            lambda *_a, **_k: PASSWORD,
        )

        path = export_backup(vault, backup, pmode, parent_seed=SEED)
        vault.save_index({"v": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["v"] == 123
