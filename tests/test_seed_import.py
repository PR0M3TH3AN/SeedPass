import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.manager import PasswordManager

SEED = "guard rule huge draft embark case any drastic horse bargain orchard mobile"


def test_seed_encryption_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))

        enc_mgr.encrypt_parent_seed(SEED)
        decrypted = enc_mgr.decrypt_parent_seed()

        assert decrypted == SEED
        pm = PasswordManager.__new__(PasswordManager)
        assert pm.validate_bip85_seed(SEED)
