import asyncio
import gzip
import math

from helpers import create_vault, dummy_nostr_client
from password_manager.entry_management import EntryManager
from nostr.client import prepare_snapshot


def test_manifest_generation(tmp_path):
    vault, enc_mgr = create_vault(tmp_path)
    entry_mgr = EntryManager(vault, tmp_path)
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
    manifest = asyncio.run(client.publish_snapshot(data, limit=50000))
    assert len(manifest.chunks) > 1
    fetched_manifest, chunk_bytes = asyncio.run(client.fetch_latest_snapshot())
    assert len(chunk_bytes) == len(manifest.chunks)
    joined = b"".join(chunk_bytes)
    assert gzip.decompress(joined) == data


def test_publish_and_fetch_deltas(dummy_nostr_client):
    client, relay = dummy_nostr_client
    base = b"base"
    manifest = asyncio.run(client.publish_snapshot(base))
    manifest_id = relay.manifests[-1].id
    d1 = b"d1"
    d2 = b"d2"
    asyncio.run(client.publish_delta(d1, manifest_id))
    asyncio.run(client.publish_delta(d2, manifest_id))
    deltas = asyncio.run(client.fetch_deltas_since(0))
    assert deltas == [d1, d2]
