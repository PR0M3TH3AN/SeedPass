import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import string

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.config_manager import ConfigManager
from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy


class DummyEnc:
    def derive_seed_from_mnemonic(self, mnemonic):
        return b"\x00" * 32


class DummyBIP85:
    def derive_entropy(self, index: int, entropy_bytes: int, app_no: int = 32) -> bytes:
        return bytes((index + i) % 256 for i in range(entropy_bytes))


def make_manager(tmp_path: Path) -> PasswordManager:
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)

    pg = PasswordGenerator.__new__(PasswordGenerator)
    pg.encryption_manager = DummyEnc()
    pg.bip85 = DummyBIP85()
    pg.policy = PasswordPolicy(
        min_uppercase=0, min_lowercase=0, min_digits=1, min_special=0
    )

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.password_generator = pg
    pm.entry_manager = entry_mgr
    pm.parent_seed = TEST_SEED
    pm.vault = vault
    pm.backup_manager = backup_mgr
    pm.nostr_client = SimpleNamespace()
    pm.fingerprint_dir = tmp_path
    pm.secret_mode_enabled = False
    return pm


def test_entry_policy_override_changes_password():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = make_manager(tmp_path)
        idx = pm.entry_manager.add_entry(
            "site",
            16,
            min_digits=5,
            include_special_chars=False,
        )
        entry = pm.entry_manager.retrieve_entry(idx)
        pw = pm._generate_password_for_entry(entry, idx)
        assert sum(c.isdigit() for c in pw) >= 5
        assert not any(c in string.punctuation for c in pw)
