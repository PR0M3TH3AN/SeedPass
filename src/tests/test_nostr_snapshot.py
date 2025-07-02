import hashlib
import json
import gzip
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet
import base64
import asyncio
from unittest.mock import patch

from nostr import prepare_snapshot, NostrClient
from password_manager.encryption import EncryptionManager


def test_prepare_snapshot_roundtrip():
    data = b"a" * 70000
    manifest, chunks = prepare_snapshot(data, 50000)
    assert len(chunks) == len(manifest.chunks)
    joined = b"".join(chunks)
    assert len(joined) <= len(data)
    assert hashlib.sha256(chunks[0]).hexdigest() == manifest.chunks[0].hash
    assert manifest.chunks[0].id == "seedpass-chunk-0000"
    assert data == gzip.decompress(joined)


class DummyEvent:
    def __init__(self, content):
        self._content = content

    def content(self):
        return self._content


class DummyClient:
    def __init__(self, events):
        self.events = events
        self.pos = 0

    async def add_relays(self, relays):
        pass

    async def add_relay(self, relay):
        pass

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def send_event(self, event):
        pass

    async def fetch_events(self, f, timeout):
        ev = self.events[self.pos]
        self.pos += 1

        class E:
            def __init__(self, ev):
                self._ev = ev

            def to_vec(self):
                return [self._ev]

        return E(ev)


def test_fetch_latest_snapshot():
    data = b"seedpass" * 1000
    manifest, chunks = prepare_snapshot(data, 50000)
    manifest_json = json.dumps(
        {
            "ver": manifest.ver,
            "algo": manifest.algo,
            "chunks": [c.__dict__ for c in manifest.chunks],
            "delta_since": None,
        }
    )
    events = [DummyEvent(manifest_json)] + [
        DummyEvent(base64.b64encode(c).decode()) for c in chunks
    ]

    client = DummyClient(events)
    with TemporaryDirectory() as tmpdir:
        enc_mgr = EncryptionManager(Fernet.generate_key(), Path(tmpdir))
        with patch("nostr.client.Client", lambda signer: client), patch(
            "nostr.client.KeyManager"
        ) as MockKM, patch.object(NostrClient, "initialize_client_pool"), patch.object(
            enc_mgr, "decrypt_parent_seed", return_value="seed"
        ):
            km = MockKM.return_value
            km.keys.private_key_hex.return_value = "1" * 64
            km.keys.public_key_hex.return_value = "2" * 64
            nc = NostrClient(enc_mgr, "fp")
            result_manifest, result_chunks = asyncio.run(nc.fetch_latest_snapshot())

    assert manifest == result_manifest
    assert result_chunks == chunks
