import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient


def setup_client(tmp_path):
    key = Fernet.generate_key()
    enc_mgr = EncryptionManager(key, tmp_path)

    with patch("nostr.client.ClientPool"), patch(
        "nostr.client.KeyManager"
    ), patch.object(NostrClient, "initialize_client_pool"), patch.object(
        enc_mgr, "decrypt_parent_seed", return_value="seed"
    ):
        client = NostrClient(enc_mgr, "fp")
    return client


class FakeEvent:
    KIND_TEXT_NOTE = 1
    KIND_ENCRYPT = 2

    def __init__(self, kind, content, pub_key):
        self.kind = kind
        self.content = content
        self.pub_key = pub_key
        self.id = "id"

    def sign(self, _):
        pass


def test_publish_json_success():
    with TemporaryDirectory() as tmpdir, patch("nostr.client.Event", FakeEvent):
        client = setup_client(Path(tmpdir))
        with patch.object(client, "publish_event") as mock_pub:
            assert client.publish_json_to_nostr(b"data") is True
            mock_pub.assert_called()


def test_publish_json_failure():
    with TemporaryDirectory() as tmpdir, patch("nostr.client.Event", FakeEvent):
        client = setup_client(Path(tmpdir))
        with patch.object(client, "publish_event", side_effect=Exception("boom")):
            assert client.publish_json_to_nostr(b"data") is False
