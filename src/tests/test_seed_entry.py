import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from mnemonic import Mnemonic

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager
from password_manager.password_generation import derive_seed_phrase
from local_bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator


def test_seed_phrase_determinism():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx_12 = entry_mgr.add_seed("seed12", TEST_SEED, words_num=12)
        idx_24 = entry_mgr.add_seed("seed24", TEST_SEED, words_num=24)

        phrase12_a = entry_mgr.get_seed_phrase(idx_12, TEST_SEED)
        phrase12_b = entry_mgr.get_seed_phrase(idx_12, TEST_SEED)
        phrase24_a = entry_mgr.get_seed_phrase(idx_24, TEST_SEED)
        phrase24_b = entry_mgr.get_seed_phrase(idx_24, TEST_SEED)

        entry12 = entry_mgr.retrieve_entry(idx_12)
        entry24 = entry_mgr.retrieve_entry(idx_24)

        seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
        bip85 = BIP85(seed_bytes)
        expected12 = derive_seed_phrase(bip85, idx_12, 12)
        expected24 = derive_seed_phrase(bip85, idx_24, 24)

        assert phrase12_a == phrase12_b == expected12
        assert phrase24_a == phrase24_b == expected24
        assert len(phrase12_a.split()) == 12
        assert len(phrase24_a.split()) == 24
        assert Mnemonic("english").check(phrase12_a)
        assert Mnemonic("english").check(phrase24_a)
        assert entry12.get("word_count") == 12
        assert entry24.get("word_count") == 24
