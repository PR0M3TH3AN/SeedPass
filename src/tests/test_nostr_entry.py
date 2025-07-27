import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from nostr.coincurve_keys import Keys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager


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
            "archived": False,
            "tags": [],
        }

        npub1, nsec1 = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)
        npub2, nsec2 = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)
        assert npub1 == npub2
        assert nsec1 == nsec2
        assert npub1.startswith("npub")
        assert nsec1.startswith("nsec")

        priv_hex = Keys.bech32_to_hex(nsec1)
        derived = Keys(priv_k=priv_hex)
        encoded_npub = Keys.hex_to_bech32(derived.public_key_hex(), "npub")
        assert encoded_npub == npub1

        data = enc_mgr.load_json_data(entry_mgr.index_file)
        assert data["entries"][str(idx)]["label"] == "main"
