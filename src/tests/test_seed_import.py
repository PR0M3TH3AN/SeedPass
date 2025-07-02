import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import TEST_PASSWORD
from utils.key_derivation import derive_key_from_password
from mnemonic import Mnemonic

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.manager import PasswordManager


def test_seed_encryption_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = derive_key_from_password(TEST_PASSWORD)
        enc_mgr = EncryptionManager(key, Path(tmpdir))

        seed = Mnemonic("english").generate(strength=128)
        enc_mgr.encrypt_parent_seed(seed)
        decrypted = enc_mgr.decrypt_parent_seed()

        assert decrypted == seed
        pm = PasswordManager.__new__(PasswordManager)
        assert pm.validate_bip85_seed(seed)
