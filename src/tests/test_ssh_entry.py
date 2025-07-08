import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager


def test_add_and_retrieve_ssh_key_pair():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        index = entry_mgr.add_ssh_key("ssh", TEST_SEED)
        entry = entry_mgr.retrieve_entry(index)
        assert entry == {
            "type": "ssh",
            "kind": "ssh",
            "index": index,
            "label": "ssh",
            "notes": "",
            "archived": False,
            "tags": [],
        }

        priv1, pub1 = entry_mgr.get_ssh_key_pair(index, TEST_SEED)
        priv2, pub2 = entry_mgr.get_ssh_key_pair(index, TEST_SEED)
        assert priv1 == priv2
        assert pub1 == pub2
