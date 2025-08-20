import asyncio
import base64
import hashlib
import json

from helpers import DummyEvent, DummyFilter, dummy_nostr_client
from nostr.backup_models import KIND_MANIFEST, KIND_SNAPSHOT_CHUNK
from nostr_sdk import Keys


def test_fetch_snapshot_legacy_key_fallback(dummy_nostr_client, monkeypatch):
    client, relay = dummy_nostr_client

    # Track legacy key generation
    called = {"legacy": False}

    class LegacyKeys:
        def private_key_hex(self):
            return "3" * 64

        def public_key_hex(self):
            return "4" * 64

    def fake_generate():
        called["legacy"] = True
        return LegacyKeys()

    monkeypatch.setattr(
        client.key_manager, "generate_legacy_nostr_keys", fake_generate, raising=False
    )

    expected_pubkey = Keys.parse("3" * 64).public_key()

    class RecordingFilter(DummyFilter):
        def author(self, pk):
            self.author_pk = pk
            return self

    monkeypatch.setattr("nostr.client.Filter", RecordingFilter)

    chunk_bytes = b"chunkdata"
    chunk_hash = hashlib.sha256(chunk_bytes).hexdigest()
    manifest_json = json.dumps(
        {
            "ver": 1,
            "algo": "gzip",
            "chunks": [
                {
                    "id": "seedpass-chunk-0000",
                    "size": len(chunk_bytes),
                    "hash": chunk_hash,
                    "event_id": None,
                }
            ],
        }
    )
    manifest_event = DummyEvent(KIND_MANIFEST, manifest_json, tags=["legacy"])
    chunk_event = DummyEvent(
        KIND_SNAPSHOT_CHUNK,
        base64.b64encode(chunk_bytes).decode("utf-8"),
        tags=["seedpass-chunk-0000"],
    )

    call = {"count": 0, "authors": []}

    async def fake_fetch_events(f, _timeout):
        call["count"] += 1
        call["authors"].append(getattr(f, "author_pk", None))
        if call["count"] == 1:
            return type("R", (), {"to_vec": lambda self: []})()
        elif call["count"] == 2:
            return type("R", (), {"to_vec": lambda self: [manifest_event]})()
        else:
            return type("R", (), {"to_vec": lambda self: [chunk_event]})()

    monkeypatch.setattr(relay, "fetch_events", fake_fetch_events)

    result = asyncio.run(client.fetch_latest_snapshot())
    assert called["legacy"]
    assert result is not None
    manifest, chunks = result
    assert b"".join(chunks) == chunk_bytes
    assert call["authors"][-1].to_hex() == expected_pubkey.to_hex()
