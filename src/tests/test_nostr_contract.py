import sys
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient


class MockNostrServer:
    def __init__(self):
        self.events = []


class MockClient:
    def __init__(self, server):
        self.server = server

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
                return "abcd"

        class FakeOutput:
            def __init__(self):
                self.id = FakeId()

        return FakeOutput()

    async def fetch_events(self, filter_obj, timeout):
        class FakeEvents:
            def __init__(self, events):
                self._events = events

            def to_vec(self):
                return self._events

        return FakeEvents(self.server.events[-1:])


def setup_client(tmp_path, server):
    key = Fernet.generate_key()
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
    assert client.publish_json_to_nostr(payload) is True
    assert client.retrieve_json_from_nostr_sync() == payload
