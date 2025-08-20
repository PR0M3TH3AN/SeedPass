import sys
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet

from helpers import TEST_PASSWORD, TEST_SEED
from utils.key_derivation import derive_key_from_password
from utils.fingerprint import generate_fingerprint

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager


def test_parent_seed_migrates_from_fernet(tmp_path: Path) -> None:
    fp = generate_fingerprint(TEST_SEED)
    key = derive_key_from_password(TEST_PASSWORD, fp)
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
    payload = json.loads(new_file.read_text())
    assert base64.b64decode(payload["ct"]).startswith(b"V2:")
