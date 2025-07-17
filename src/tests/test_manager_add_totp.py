import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.config_manager import ConfigManager


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_handle_add_totp(monkeypatch, capsys):
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
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False

        inputs = iter(
            [
                "1",  # choose derive
                "Example",  # label
                "",  # period
                "",  # digits
                "",  # notes
                "",  # tags
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))
        monkeypatch.setattr(
            pm, "start_background_vault_sync", lambda *a, **k: pm.sync_vault(*a, **k)
        )

        pm.handle_add_totp()
        out = capsys.readouterr().out

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "type": "totp",
            "kind": "totp",
            "label": "Example",
            "index": 0,
            "period": 30,
            "digits": 6,
            "archived": False,
            "notes": "",
            "tags": [],
        }
        assert "ID 0" in out
