import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import asyncio
import pytest
import os
import base64

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager
from nostr.client import NostrClient, Manifest


def setup_client(tmp_path):
    key = base64.urlsafe_b64encode(os.urandom(32))
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
            with patch("nostr.snapshot.new_manifest_id", return_value=("id", b"nonce")):
                manifest, event_id = asyncio.run(client.publish_snapshot(b"data"))
            assert isinstance(manifest, Manifest)
            assert event_id == "id"
            assert manifest.nonce == base64.b64encode(b"nonce").decode("utf-8")
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
