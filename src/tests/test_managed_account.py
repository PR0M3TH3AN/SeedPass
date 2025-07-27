import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint
import seedpass.core.manager as manager_module
from seedpass.core.manager import EncryptionMode

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def setup_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    backup = BackupManager(tmp_path, cfg)
    return EntryManager(vault, backup)


def test_add_managed_account_fields_and_dir():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = setup_entry_manager(tmp_path)

        idx = mgr.add_managed_account("acct", TEST_SEED)
        entry = mgr.retrieve_entry(idx)

        assert entry["type"] == "managed_account"
        assert entry["kind"] == "managed_account"
        assert entry["index"] == idx
        assert entry["label"] == "acct"
        assert entry["word_count"] == 12
        assert entry["archived"] is False
        fp = entry.get("fingerprint")
        assert fp
        assert (tmp_path / "accounts" / fp).exists()

        seed = mgr.get_managed_account_seed(idx, TEST_SEED)
        assert generate_fingerprint(seed) == fp


def test_load_and_exit_managed_account(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_managed_account("acct", TEST_SEED)
        seed = entry_mgr.get_managed_account_seed(idx, TEST_SEED)
        fp = generate_fingerprint(seed)
        acct_dir = tmp_path / "accounts" / fp

        pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.config_manager = cfg_mgr
        pm.parent_seed = TEST_SEED
        pm.current_fingerprint = "rootfp"
        pm.fingerprint_dir = tmp_path
        pm.profile_stack = []
        monkeypatch.setattr(pm, "initialize_bip85", lambda: None)
        monkeypatch.setattr(pm, "initialize_managers", lambda: None)
        monkeypatch.setattr(pm, "sync_index_from_nostr_if_missing", lambda: None)
        monkeypatch.setattr(pm, "sync_index_from_nostr", lambda: None)
        monkeypatch.setattr(pm, "update_activity", lambda: None)

        pm.load_managed_account(idx)

        assert pm.current_fingerprint == fp
        assert pm.fingerprint_dir == acct_dir
        assert pm.profile_stack[-1][0] == "rootfp"
        assert pm.profile_stack[-1][1] == tmp_path

        pm.exit_managed_account()

        assert pm.current_fingerprint == "rootfp"
        assert pm.fingerprint_dir == tmp_path
        assert pm.profile_stack == []
