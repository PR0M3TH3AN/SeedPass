import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import json

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.totp import TotpManager


class FakeNostrClient:
    def publish_snapshot(self, data: bytes):
        return None, "abcd"


def test_handle_export_totp_codes(monkeypatch, tmp_path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    entry_mgr = EntryManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.parent_seed = TEST_SEED
    pm.nostr_client = FakeNostrClient()
    pm.fingerprint_dir = tmp_path

    # add totp entries
    entry_mgr.add_totp("Example", TEST_SEED)
    entry_mgr.add_totp("Imported", TEST_SEED, secret="JBSWY3DPEHPK3PXP")

    export_path = tmp_path / "out.json"
    monkeypatch.setattr("builtins.input", lambda *a, **k: str(export_path))
    monkeypatch.setattr(
        "password_manager.manager.confirm_action", lambda *_a, **_k: False
    )

    pm.handle_export_totp_codes()

    data = json.loads(export_path.read_text())
    assert len(data["entries"]) == 2
    labels = {e["label"] for e in data["entries"]}
    assert {"Example", "Imported"} == labels
    # check URI format
    uri = data["entries"][0]["uri"]
    assert uri.startswith("otpauth://totp/")
