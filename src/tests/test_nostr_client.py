import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import asyncio
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient
import nostr.client as nostr_client


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


class FakeWebSocket:
    def __init__(self, messages):
        self.messages = messages

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

    async def send(self, _):
        pass

    async def recv(self):
        if self.messages:
            return self.messages.pop(0)
        await asyncio.sleep(0)


def _setup_client(tmpdir, fake_cls):
    key = Fernet.generate_key()
    enc_mgr = EncryptionManager(key, Path(tmpdir))

    with patch("nostr.client.Client", fake_cls), patch(
        "nostr.client.KeyManager"
    ) as MockKM, patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"):
        km_inst = MockKM.return_value
        km_inst.keys.private_key_hex.return_value = "1" * 64
        client = NostrClient(enc_mgr, "fp")
    return client


def test_initialize_client_pool_add_relays_used(tmp_path):
    client = _setup_client(tmp_path, FakeAddRelaysClient)
    fc = client.client
    client.connect()
    assert fc.added == [client.relays]
    assert fc.connected is True


def test_initialize_client_pool_add_relay_fallback(tmp_path):
    client = _setup_client(tmp_path, FakeAddRelayClient)
    fc = client.client
    client.connect()
    assert fc.added == client.relays
    assert fc.connected is True


def test_check_relay_health_runs_async(tmp_path, monkeypatch):
    client = _setup_client(tmp_path, FakeAddRelayClient)

    recorded = {}

    async def fake_check(min_relays, timeout):
        recorded["args"] = (min_relays, timeout)
        return 1

    monkeypatch.setattr(client, "_check_relay_health", fake_check)
    result = client.check_relay_health(3, timeout=2)

    assert result == 1
    assert recorded["args"] == (3, 2)


def test_ping_relay_accepts_eose(tmp_path, monkeypatch):
    client = _setup_client(tmp_path, FakeAddRelayClient)

    fake_ws = FakeWebSocket([json.dumps(["EOSE"])])

    def fake_connect(*_args, **_kwargs):
        return fake_ws

    monkeypatch.setattr(nostr_client.websockets, "connect", fake_connect)

    result = asyncio.run(client._ping_relay("wss://relay", timeout=0.1))

    assert result is True
