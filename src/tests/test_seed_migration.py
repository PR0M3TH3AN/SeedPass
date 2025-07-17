import sys
from pathlib import Path
from cryptography.fernet import Fernet

from helpers import TEST_PASSWORD, TEST_SEED
from utils.key_derivation import derive_key_from_password

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager


def test_parent_seed_migrates_from_fernet(tmp_path: Path) -> None:
    key = derive_key_from_password(TEST_PASSWORD)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(TEST_SEED.encode())
    legacy_file = tmp_path / "parent_seed.enc"
    legacy_file.write_bytes(encrypted)

    manager = EncryptionManager(key, tmp_path)
    decrypted = manager.decrypt_parent_seed()

    assert decrypted == TEST_SEED

    new_file = tmp_path / "parent_seed.enc"

    assert new_file.exists()
    assert new_file.read_bytes() != encrypted
    assert new_file.read_bytes().startswith(b"V2:")
