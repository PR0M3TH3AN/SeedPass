import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.vault import Vault
from nostr.client import NostrClient


def test_backup_and_publish_to_nostr():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, tmp_path)
        vault = Vault(enc_mgr, tmp_path)
        entry_mgr = EntryManager(vault, tmp_path)

        # create an index by adding an entry
        entry_mgr.add_entry("example.com", 12)
        encrypted_index = entry_mgr.get_encrypted_index()
        assert encrypted_index is not None

        with patch(
            "nostr.client.NostrClient.publish_json_to_nostr"
        ) as mock_publish, patch("nostr.client.ClientPool"), patch(
            "nostr.client.KeyManager"
        ), patch.object(
            NostrClient, "initialize_client_pool"
        ), patch.object(
            enc_mgr, "decrypt_parent_seed", return_value="seed"
        ):
            nostr_client = NostrClient(enc_mgr, "fp")
            entry_mgr.backup_index_file()
            nostr_client.publish_json_to_nostr(encrypted_index)

        mock_publish.assert_called_with(encrypted_index)
