import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import asyncio
import pytest
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient, Manifest


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
    def __init__(self, content="evt"):
        self._id = "id"
        self._content = content

    def id(self):
        return self._id

    def content(self):
        return self._content


class FakeUnsignedEvent:
    def __init__(self, content="evt"):
        self._content = content

    def sign_with_keys(self, _):
        return FakeEvent(self._content)


class FakeBuilder:
    def __init__(self, _kind=None, content="evt"):
        self._content = content

    def tags(self, _tags):
        return self

    def build(self, _):
        return FakeUnsignedEvent(self._content)


class FakeEventId:
    def to_hex(self):
        return "abcd"


class FakeSendEventOutput:
    def __init__(self):
        self.id = FakeEventId()


def test_publish_snapshot_success():
    with TemporaryDirectory() as tmpdir, patch(
        "nostr.client.EventBuilder", FakeBuilder
    ):
        client = setup_client(Path(tmpdir))

        async def fake_send(event):
            return FakeSendEventOutput()

        with patch.object(
            client.client, "send_event", side_effect=fake_send
        ) as mock_send:
            manifest, event_id = asyncio.run(client.publish_snapshot(b"data"))
            assert isinstance(manifest, Manifest)
            assert event_id == "abcd"
            assert mock_send.await_count >= 1


def test_publish_snapshot_failure():
    with TemporaryDirectory() as tmpdir, patch(
        "nostr.client.EventBuilder", FakeBuilder
    ):
        client = setup_client(Path(tmpdir))

        async def boom(_):
            raise Exception("boom")

        with patch.object(client.client, "send_event", side_effect=boom):
            with pytest.raises(Exception):
                asyncio.run(client.publish_snapshot(b"data"))
