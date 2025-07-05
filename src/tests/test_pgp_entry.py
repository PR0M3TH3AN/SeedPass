import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def test_pgp_key_determinism():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_pgp_key(TEST_SEED, key_type="ed25519", user_id="Test")
        key1, fp1 = entry_mgr.get_pgp_key(idx, TEST_SEED)
        key2, fp2 = entry_mgr.get_pgp_key(idx, TEST_SEED)

        assert fp1 == fp2
        assert key1 == key2

        # parse returned armored key and verify fingerprint
        from pgpy import PGPKey

        parsed_key, _ = PGPKey.from_blob(key1)
        assert parsed_key.fingerprint == fp1

        # ensure the index file stores key_type and user_id
        data = enc_mgr.load_json_data(entry_mgr.index_file)
        entry = data["entries"][str(idx)]
        assert entry["key_type"] == "ed25519"
        assert entry["user_id"] == "Test"
