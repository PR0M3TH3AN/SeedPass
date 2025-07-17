import asyncio
import gzip
import math

from helpers import create_vault, dummy_nostr_client
from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager
from nostr.client import prepare_snapshot
from nostr.backup_models import KIND_SNAPSHOT_CHUNK


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
    manifest_id = relay.manifests[-1].id
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
