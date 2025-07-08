import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager
from password_manager.password_generation import derive_seed_phrase
from local_bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator


def setup_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    backup = BackupManager(tmp_path, cfg)
    return EntryManager(vault, backup)


def test_add_and_get_managed_account_seed():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        mgr = setup_mgr(tmp_path)

        idx = mgr.add_managed_account("acct", TEST_SEED, word_count=12)
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

        phrase_a = mgr.get_managed_account_seed(idx, TEST_SEED)
        phrase_b = mgr.get_managed_account_seed(idx, TEST_SEED)
        assert phrase_a == phrase_b

        seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
        bip85 = BIP85(seed_bytes)
        expected = derive_seed_phrase(bip85, idx, 12)
        assert phrase_a == expected
        assert generate_fingerprint(phrase_a) == fp
