import hashlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.fingerprint import generate_fingerprint
from password_manager.encryption import EncryptionManager


def test_generate_fingerprint_deterministic():
    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    expected = (
        hashlib.sha256(seed.strip().lower().encode("utf-8")).hexdigest()[:16].upper()
    )
    fp1 = generate_fingerprint(seed)
    fp2 = generate_fingerprint(seed.upper())
    assert fp1 == expected
    assert fp1 == fp2


def test_encryption_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        manager = EncryptionManager(key, Path(tmpdir))
        data = b"secret data"
        rel_path = Path("testfile.enc")
        manager.encrypt_and_save_file(data, rel_path)
        decrypted = manager.decrypt_file(rel_path)
        assert decrypted == data

        # parent seed round trip
        seed = "correct horse battery staple"
        manager.encrypt_parent_seed(seed)
        assert manager.decrypt_parent_seed() == seed
