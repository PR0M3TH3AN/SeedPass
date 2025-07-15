import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager

import pytest


@pytest.mark.parametrize(
    "adder,needs_confirm",
    [
        (lambda mgr: mgr.add_seed("seed", TEST_SEED), True),
        (lambda mgr: mgr.add_pgp_key("pgp", TEST_SEED, user_id="test"), True),
        (lambda mgr: mgr.add_ssh_key("ssh", TEST_SEED), True),
        (lambda mgr: mgr.add_nostr_key("nostr"), False),
    ],
)
def test_pause_before_entry_actions(monkeypatch, adder, needs_confirm):
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
        pm.parent_seed = TEST_SEED
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False

        index = adder(entry_mgr)

        pause_calls = []
        monkeypatch.setattr(
            "password_manager.manager.pause", lambda *a, **k: pause_calls.append(True)
        )
        monkeypatch.setattr(pm, "_entry_actions_menu", lambda *a, **k: None)
        monkeypatch.setattr("builtins.input", lambda *a, **k: str(index))
        if needs_confirm:
            monkeypatch.setattr(
                "password_manager.manager.confirm_action", lambda *a, **k: True
            )

        pm.handle_retrieve_entry()
        assert len(pause_calls) == 1
