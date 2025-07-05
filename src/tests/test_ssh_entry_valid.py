import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager
from cryptography.hazmat.primitives import serialization


def test_ssh_private_key_corresponds_to_public():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_ssh_key(TEST_SEED)
        priv_pem, pub_pem = entry_mgr.get_ssh_key_pair(idx, TEST_SEED)

        priv_key = serialization.load_pem_private_key(
            priv_pem.encode(),
            password=None,
        )
        derived_pub_pem = (
            priv_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        assert derived_pub_pem == pub_pem
