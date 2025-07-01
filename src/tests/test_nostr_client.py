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

        with (
            patch("nostr.client.ClientBuilder") as MockBuilder,
            patch("nostr.client.KeyManager"),
            patch.object(NostrClient, "initialize_client_pool"),
        ):
            mock_builder = MockBuilder.return_value
            with patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"):
                client = NostrClient(enc_mgr, "fp", relays=custom_relays)

        assert client.relays == custom_relays


class FakeAddRelaysClient:
    def __init__(self, _signer):
        self.added = []
        self.connected = False

    async def add_relays(self, relays):
        self.added.append(relays)

    async def connect(self):
        self.connected = True


class FakeAddRelayClient:
    def __init__(self, _signer):
        self.added = []
        self.connected = False

    async def add_relay(self, relay):
        self.added.append(relay)

    async def connect(self):
        self.connected = True


def _setup_client(tmpdir, fake_cls):
    key = Fernet.generate_key()
    enc_mgr = EncryptionManager(key, Path(tmpdir))

    with (
        patch("nostr.client.Client", fake_cls),
        patch("nostr.client.KeyManager") as MockKM,
        patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"),
    ):
        km_inst = MockKM.return_value
        km_inst.keys.private_key_hex.return_value = "1" * 64
        client = NostrClient(enc_mgr, "fp")
    return client


def test_initialize_client_pool_add_relays_used(tmp_path):
    client = _setup_client(tmp_path, FakeAddRelaysClient)
    fc = client.client
    assert fc.added == [client.relays]
    assert fc.connected is True


def test_initialize_client_pool_add_relay_fallback(tmp_path):
    client = _setup_client(tmp_path, FakeAddRelayClient)
    fc = client.client
    assert fc.added == client.relays
    assert fc.connected is True
