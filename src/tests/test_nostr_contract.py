import sys
from pathlib import Path
from unittest.mock import patch
import asyncio
import gzip
import os
import base64

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient, Manifest


class MockNostrServer:
    def __init__(self):
        self.events = []


class MockClient:
    def __init__(self, server):
        self.server = server
        self.pos = -1

    async def add_relays(self, relays):
        pass

    async def add_relay(self, relay):
        pass

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def send_event(self, event):
        self.server.events.append(event)

        class FakeId:
            def to_hex(self_inner):
                return "a" * 64

        class FakeOutput:
            def __init__(self):
                self.id = FakeId()

        return FakeOutput()

    async def fetch_events(self, filter_obj, timeout):
        ev = self.server.events[self.pos]
        self.pos -= 1

        class FakeEvents:
            def __init__(self, event):
                self._event = event

            def to_vec(self):
                return [self._event]

        return FakeEvents(ev)


def setup_client(tmp_path, server):
    key = base64.urlsafe_b64encode(os.urandom(32))
    enc_mgr = EncryptionManager(key, tmp_path)

    with patch("nostr.client.Client", lambda signer: MockClient(server)), patch(
        "nostr.client.KeyManager"
    ) as MockKM, patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"):
        km_inst = MockKM.return_value
        km_inst.keys.private_key_hex.return_value = "1" * 64
        km_inst.keys.public_key_hex.return_value = "2" * 64
        client = NostrClient(enc_mgr, "fp", relays=["ws://mock"])
    return client


def test_publish_and_retrieve(tmp_path):
    server = MockNostrServer()
    client = setup_client(tmp_path, server)
    payload = b"contract-test"
    asyncio.run(client.publish_snapshot(payload))
    manifest, chunks = asyncio.run(client.fetch_latest_snapshot())
    assert gzip.decompress(b"".join(chunks)) == payload
