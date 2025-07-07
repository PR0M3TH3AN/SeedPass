import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


def test_retrieve_entry_shows_custom_fields(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.password_generator = SimpleNamespace(generate_password=lambda l, i: "pw")
        pm.parent_seed = TEST_SEED
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False

        entry_mgr.add_entry(
            "example",
            8,
            custom_fields=[
                {"label": "visible", "value": "shown", "is_hidden": False},
                {"label": "token", "value": "secret", "is_hidden": True},
            ],
        )

        inputs = iter(["0", "y", "n"])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert "Additional Fields:" in out
        assert "visible: shown" in out
        assert "token" in out
        assert "secret" in out
