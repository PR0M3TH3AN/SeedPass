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

    with patch("nostr.client.ClientBuilder"), patch(
        "nostr.client.KeyManager"
    ) as MockKM, patch.object(NostrClient, "initialize_client_pool"), patch.object(
        enc_mgr, "decrypt_parent_seed", return_value="seed"
    ):
        km_inst = MockKM.return_value
        km_inst.keys.private_key_hex.return_value = "1" * 64
        km_inst.keys.public_key_hex.return_value = "2" * 64
        client = NostrClient(enc_mgr, "fp")
    return client


class FakeEvent:
    def __init__(self):
        self._id = "id"

    def id(self):
        return self._id


class FakeUnsignedEvent:
    def sign_with_keys(self, _):
        return FakeEvent()


class FakeBuilder:
    def build(self, _):
        return FakeUnsignedEvent()


def test_publish_json_success():
    with TemporaryDirectory() as tmpdir, patch(
        "nostr.client.EventBuilder.text_note", return_value=FakeBuilder()
    ):
        client = setup_client(Path(tmpdir))
        with patch.object(client, "publish_event") as mock_pub:
            assert client.publish_json_to_nostr(b"data") is True
            mock_pub.assert_called()


def test_publish_json_failure():
    with TemporaryDirectory() as tmpdir, patch(
        "nostr.client.EventBuilder.text_note", return_value=FakeBuilder()
    ):
        client = setup_client(Path(tmpdir))
        with patch.object(client, "publish_event", side_effect=Exception("boom")):
            assert client.publish_json_to_nostr(b"data") is False
