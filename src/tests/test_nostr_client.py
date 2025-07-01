import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient


def test_nostr_client_uses_custom_relays():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        custom_relays = ["wss://relay1", "wss://relay2"]

        with patch("nostr.client.ClientBuilder") as MockBuilder, patch(
            "nostr.client.KeyManager"
        ), patch.object(NostrClient, "initialize_client_pool"):
            mock_builder = MockBuilder.return_value
            with patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"):
                client = NostrClient(enc_mgr, "fp", relays=custom_relays)

        assert client.relays == custom_relays
