import asyncio
import gzip
import math
import pytest

from helpers import create_vault, dummy_nostr_client, TEST_SEED
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from nostr.client import prepare_snapshot
from nostr.backup_models import KIND_SNAPSHOT_CHUNK
import constants


def test_manifest_generation(tmp_path):
    vault, enc_mgr = create_vault(tmp_path)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)
    entry_mgr.add_entry("example.com", 12)
    entry_mgr.add_entry("test.com", 12)
    encrypted = vault.get_encrypted_index()
    assert encrypted
    manifest, chunks = prepare_snapshot(encrypted, 100)
    compressed = gzip.compress(encrypted)
    expected = math.ceil(len(compressed) / 100)
    assert len(chunks) == expected
    assert len(manifest.chunks) == expected
    for meta in manifest.chunks:
        assert meta.id
        assert meta.hash


def test_retrieve_multi_chunk_snapshot(dummy_nostr_client):
    import os

    client, relay = dummy_nostr_client
    data = os.urandom(120000)
    manifest, _ = asyncio.run(client.publish_snapshot(data, limit=50000))
    assert len(manifest.chunks) > 1
    for meta in manifest.chunks:
        assert meta.event_id
    fetched_manifest, chunk_bytes = asyncio.run(client.fetch_latest_snapshot())
    assert len(chunk_bytes) == len(manifest.chunks)
    assert [c.event_id for c in fetched_manifest.chunks] == [
        c.event_id for c in manifest.chunks
    ]
    joined = b"".join(chunk_bytes)
    assert gzip.decompress(joined) == data
    for f in relay.filters:
        if getattr(f, "kind_val", None) == KIND_SNAPSHOT_CHUNK:
            assert f.id_called


def test_publish_and_fetch_deltas(dummy_nostr_client):
    client, relay = dummy_nostr_client
    base = b"base"
    manifest, _ = asyncio.run(client.publish_snapshot(base))
    manifest_id = relay.manifests[-1].tags[0]
    d1 = b"d1"
    d2 = b"d2"
    asyncio.run(client.publish_delta(d1, manifest_id))
    first_ts = relay.deltas[-1].created_at
    asyncio.run(client.publish_delta(d2, manifest_id))
    second_ts = relay.deltas[-1].created_at
    assert second_ts > first_ts
    assert relay.manifests[-1].delta_since == second_ts
    deltas = asyncio.run(client.fetch_deltas_since(0))
    assert deltas == [d1, d2]


def test_fetch_snapshot_fallback_on_missing_chunk(dummy_nostr_client, monkeypatch):
    import os
    import gzip

    client, relay = dummy_nostr_client
    monkeypatch.setattr("nostr.client.MAX_RETRIES", 3)
    monkeypatch.setattr("nostr.client.RETRY_DELAY", 1)
    monkeypatch.setattr("constants.MAX_RETRIES", 3)
    monkeypatch.setattr("constants.RETRY_DELAY", 1)
    monkeypatch.setattr("seedpass.core.config_manager.MAX_RETRIES", 3)
    monkeypatch.setattr("seedpass.core.config_manager.RETRY_DELAY", 1)
    delays: list[float] = []

    async def fake_sleep(d):
        delays.append(d)

    monkeypatch.setattr("nostr.client.asyncio.sleep", fake_sleep)

    data1 = os.urandom(60000)
    manifest1, _ = asyncio.run(client.publish_snapshot(data1))

    data2 = os.urandom(60000)
    manifest2, _ = asyncio.run(client.publish_snapshot(data2))

    missing = manifest2.chunks[0]
    if missing.event_id:
        relay.chunks.pop(missing.event_id, None)
    relay.chunks.pop(missing.id, None)

    relay.filters.clear()

    result = asyncio.run(client.fetch_latest_snapshot())

    assert result is None

    attempts = sum(
        1
        for f in relay.filters
        if getattr(f, "kind_val", None) == KIND_SNAPSHOT_CHUNK
        and (
            missing.id in getattr(f, "ids", [])
            or (missing.event_id and missing.event_id in getattr(f, "ids", []))
        )
    )
    assert attempts == 3
    assert delays == [1, 2]


def test_fetch_snapshot_uses_event_ids(dummy_nostr_client):
    import os
    import gzip

    client, relay = dummy_nostr_client

    data = os.urandom(60000)
    manifest, _ = asyncio.run(client.publish_snapshot(data))

    # Remove identifier keys so chunks can only be fetched via event_id
    for meta in manifest.chunks:
        relay.chunks.pop(meta.id, None)

    relay.filters.clear()

    fetched_manifest, chunk_bytes = asyncio.run(client.fetch_latest_snapshot())

    assert gzip.decompress(b"".join(chunk_bytes)) == data

    id_filters = [
        f.id_called
        for f in relay.filters
        if getattr(f, "kind_val", None) == KIND_SNAPSHOT_CHUNK
    ]
    assert id_filters and all(id_filters)


def test_publish_delta_aborts_if_outdated(tmp_path, monkeypatch, dummy_nostr_client):
    client1, relay = dummy_nostr_client

    from cryptography.fernet import Fernet
    from nostr.client import NostrClient
    from seedpass.core.encryption import EncryptionManager

    enc_mgr = EncryptionManager(Fernet.generate_key(), tmp_path)

    class DummyKeys:
        def private_key_hex(self):
            return "1" * 64

        def public_key_hex(self):
            return "2" * 64

    class DummyKeyManager:
        def __init__(self, *a, **k):
            self.keys = DummyKeys()

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("nostr.client.KeyManager", DummyKeyManager)
        mp.setattr(enc_mgr, "decrypt_parent_seed", lambda: TEST_SEED)
        client2 = NostrClient(enc_mgr, "fp")

    base = b"base"
    manifest, _ = asyncio.run(client1.publish_snapshot(base))
    with client1._state_lock:
        client1.current_manifest.delta_since = 0
    import copy

    with client2._state_lock:
        client2.current_manifest = copy.deepcopy(manifest)
        client2.current_manifest_id = manifest_id = relay.manifests[-1].tags[0]

    asyncio.run(client2.publish_delta(b"d1", manifest_id))

    with pytest.raises(RuntimeError):
        asyncio.run(client1.publish_delta(b"d2", manifest_id))
