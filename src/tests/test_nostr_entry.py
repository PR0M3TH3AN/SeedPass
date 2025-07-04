import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager


def test_nostr_key_determinism():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_nostr_key("main")
        entry = entry_mgr.retrieve_entry(idx)
        assert entry == {
            "type": "nostr",
            "kind": "nostr",
            "index": idx,
            "label": "main",
            "notes": "",
        }

        npub1, nsec1 = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)
        npub2, nsec2 = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)
        assert npub1 == npub2
        assert nsec1 == nsec2
        assert npub1.startswith("npub")
        assert nsec1.startswith("nsec")
