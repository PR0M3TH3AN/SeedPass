import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.vault import Vault
from password_manager.encryption import EncryptionManager
from utils.key_derivation import (
    derive_index_key,
    derive_key_from_password,
    EncryptionMode,
)

TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_PASSWORD = "pw"


def create_vault(
    dir_path: Path,
    seed: str = TEST_SEED,
    password: str = TEST_PASSWORD,
    mode: EncryptionMode = EncryptionMode.SEED_ONLY,
) -> tuple[Vault, EncryptionManager]:
    """Create a Vault initialized for tests."""
    seed_key = derive_key_from_password(password)
    seed_mgr = EncryptionManager(seed_key, dir_path)
    seed_mgr.encrypt_parent_seed(seed)

    index_key = derive_index_key(seed, password, mode)
    enc_mgr = EncryptionManager(index_key, dir_path)
    vault = Vault(enc_mgr, dir_path)
    return vault, enc_mgr
