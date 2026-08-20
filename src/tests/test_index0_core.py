from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault
from nostr.backup_models import ChunkMeta, Manifest
from seedpass.core.index0 import (
    compute_event_hash,
    compute_event_id,
    ensure_index0_payload,
    merge_system_index0,
    normalize_index0,
)


def test_ensure_index0_payload_initializes_reserved_namespace():
    payload = ensure_index0_payload({"schema_version": 4, "entries": {}})

    assert payload["_system"]["index0"]["schema_version"] == 1
    assert payload["_system"]["index0"]["events"] == {}
    assert payload["_system"]["index0"]["canonical_views"] == {}
    assert payload["_system"]["index0"]["stats"]["event_count"] == 0


def test_merge_system_index0_is_order_independent_for_events_and_heads():
    base_event = {
        "event_type": "entry_modified",
        "subject_type": "entry",
        "subject_id": "1",
        "subject_kind": "password",
        "scope_path": "seed/root",
        "actor_type": "user",
        "actor_id": "fp1",
        "writer_id": "writer:profile:fp1",
        "modified_ts": 100,
        "payload_ref": {"entry_id": "1"},
        "links": [],
        "tags": ["b", "a"],
        "visibility": "private",
        "classification": "internal",
        "partition": "standard",
    }
    event_a = dict(base_event)
    event_a["integrity_hash"] = compute_event_hash(event_a)
    event_a["event_id"] = compute_event_id(event_a)
    event_b = dict(base_event)
    event_b["modified_ts"] = 200
    event_b["prev_hash"] = "prev"
    event_b["integrity_hash"] = compute_event_hash(event_b)
    event_b["event_id"] = compute_event_id(event_b)

    current = normalize_index0(
        {
            "events": {event_a["event_id"]: event_a},
            "heads": {
                "writer:profile:fp1": {
                    "event_id": event_a["event_id"],
                    "head_hash": "aaa",
                    "modified_ts": 100,
                }
            },
        }
    )
    incoming = normalize_index0(
        {
            "events": {event_b["event_id"]: event_b},
            "heads": {
                "writer:profile:fp1": {
                    "event_id": event_b["event_id"],
                    "head_hash": "bbb",
                    "modified_ts": 200,
                }
            },
        }
    )

    ab = merge_system_index0(current, incoming)
    ba = merge_system_index0(incoming, current)

    assert ab == ba
    assert ab["stats"]["event_count"] == 2
    assert ab["heads"]["writer:profile:fp1"]["head_hash"] == "bbb"


def test_vault_save_and_load_index_normalizes_index0_namespace():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        vault, _ = create_vault(base)
        vault.save_index({"schema_version": 4, "entries": {}})

        loaded = vault.load_index()

        assert "_system" in loaded
        assert "index0" in loaded["_system"]
        assert loaded["_system"]["index0"]["stats"]["writer_count"] == 0


def test_manifest_supports_optional_index0_metadata_round_trip():
    manifest = Manifest(
        ver=1,
        algo="gzip",
        chunks=[ChunkMeta(id="c1", size=10, hash="abc", event_id="evt1")],
        delta_since=123,
        nonce="nonce",
        index0={
            "schema_version": 1,
            "checkpoint_ids": ["cp:day:2026-03-05:writer:profile:fp1"],
            "checkpoint_hashes": {"cp:day:2026-03-05:writer:profile:fp1": "abc123"},
            "stream_heads": {"writer:profile:fp1": "head123"},
        },
    )
    payload = {
        "ver": manifest.ver,
        "algo": manifest.algo,
        "chunks": [meta.__dict__ for meta in manifest.chunks],
        "delta_since": manifest.delta_since,
        "nonce": manifest.nonce,
        "index0": manifest.index0,
    }

    parsed = Manifest(
        ver=payload["ver"],
        algo=payload["algo"],
        chunks=[ChunkMeta(**chunk) for chunk in payload["chunks"]],
        delta_since=payload["delta_since"],
        nonce=payload["nonce"],
        index0=payload["index0"],
    )

    assert parsed.index0 is not None
    assert parsed.index0["stream_heads"]["writer:profile:fp1"] == "head123"
