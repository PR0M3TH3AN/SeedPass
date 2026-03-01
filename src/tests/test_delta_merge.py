from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from helpers import create_vault
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.sync_conflict import merge_index_payloads


def _setup_mgr(path: Path):
    vault, _ = create_vault(path)
    cfg = ConfigManager(vault, path)
    backup = BackupManager(path, cfg)
    return vault, EntryManager(vault, backup)


def test_merge_modified_ts():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        va, ema = _setup_mgr(base / "A")
        vb, emb = _setup_mgr(base / "B")

        idx0 = ema.add_entry("a", 8)
        idx1 = ema.add_entry("b", 8)

        # B starts from A's snapshot
        enc = va.get_encrypted_index() or b""
        vb.decrypt_and_save_index_from_nostr(enc, merge=False)
        emb.clear_cache()
        assert emb.retrieve_entry(idx0)["username"] == ""

        ema.modify_entry(idx0, username="ua")
        data_a = va.load_index()
        data_a["entries"][str(idx0)]["modified_ts"] = (
            int(data_a["entries"][str(idx0)].get("modified_ts", 0)) + 1
        )
        va.save_index(data_a)
        delta_a = va.get_encrypted_index() or b""
        vb.decrypt_and_save_index_from_nostr(delta_a, merge=True)
        emb.clear_cache()
        assert emb.retrieve_entry(idx0)["username"] == "ua"

        emb.modify_entry(idx1, username="ub")
        data_b = vb.load_index()
        data_b["entries"][str(idx1)]["modified_ts"] = (
            int(data_b["entries"][str(idx1)].get("modified_ts", 0)) + 1
        )
        vb.save_index(data_b)
        delta_b = vb.get_encrypted_index() or b""
        va.decrypt_and_save_index_from_nostr(delta_b, merge=True)
        ema.clear_cache()
        assert ema.retrieve_entry(idx1)["username"] == "ub"

        assert ema.retrieve_entry(idx0)["username"] == "ua"
        assert ema.retrieve_entry(idx1)["username"] == "ub"
        assert emb.retrieve_entry(idx0)["username"] == "ua"
        assert emb.retrieve_entry(idx1)["username"] == "ub"


def test_merge_replay_idempotent_through_vault_boundary():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        va, ema = _setup_mgr(base / "A")
        vb, emb = _setup_mgr(base / "B")

        idx = ema.add_entry("svc", 12)
        snapshot = va.get_encrypted_index() or b""
        vb.decrypt_and_save_index_from_nostr(snapshot, merge=False)
        ema.modify_entry(idx, username="alice")
        data_a = va.load_index()
        data_a["entries"][str(idx)]["modified_ts"] = (
            int(data_a["entries"][str(idx)].get("modified_ts", 0)) + 1
        )
        va.save_index(data_a)
        payload = va.get_encrypted_index() or b""

        # First merge apply.
        vb.decrypt_and_save_index_from_nostr(payload, merge=True)
        emb.clear_cache()
        first = vb.load_index()
        assert emb.retrieve_entry(idx)["username"] == "alice"

        # Replay same payload should be idempotent.
        vb.decrypt_and_save_index_from_nostr(payload, merge=True)
        emb.clear_cache()
        second = vb.load_index()
        assert second == first


def test_merge_conflict_equal_timestamp_order_independent():
    current = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "alice",
            }
        },
    }
    incoming_a = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "bob",
            }
        },
    }
    incoming_b = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "carol",
            }
        },
    }

    ab = merge_index_payloads(
        merge_index_payloads(current, incoming_a, source_tag="a"),
        incoming_b,
        source_tag="b",
    )
    ba = merge_index_payloads(
        merge_index_payloads(current, incoming_b, source_tag="b"),
        incoming_a,
        source_tag="a",
    )
    assert ab["entries"]["1"] == ba["entries"]["1"]
    assert ab["_sync_meta"]["strategy"] == "modified_ts_hash_tombstone_v2"
    assert sorted(ab["_sync_meta"]["sources"]) == ["a", "b"]


def test_merge_conflict_equal_timestamp_field_level_union():
    current = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "",
                "url": "https://example.com",
                "notes": "",
            }
        },
    }
    incoming = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "alice",
                "url": "",
                "notes": "prod account",
                "archived": True,
            }
        },
    }
    merged = merge_index_payloads(current, incoming, source_tag="n1")
    entry = merged["entries"]["1"]
    assert entry["username"] == "alice"
    assert entry["url"] == "https://example.com"
    assert entry["notes"] == "prod account"
    assert entry["archived"] is True


def test_merge_conflict_equal_timestamp_field_union_order_independent():
    base = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 200,
                "username": "",
                "url": "",
                "notes": "",
            }
        },
    }
    a = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 200,
                "username": "alice",
                "url": "",
                "notes": "",
            }
        },
    }
    b = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "x",
                "modified_ts": 200,
                "username": "",
                "url": "https://example.com",
                "notes": "note",
            }
        },
    }
    ab = merge_index_payloads(
        merge_index_payloads(base, a, source_tag="a"), b, source_tag="b"
    )
    ba = merge_index_payloads(
        merge_index_payloads(base, b, source_tag="b"), a, source_tag="a"
    )
    assert ab["entries"]["1"] == ba["entries"]["1"]
    assert ab["entries"]["1"]["username"] == "alice"
    assert ab["entries"]["1"]["url"] == "https://example.com"
    assert ab["entries"]["1"]["notes"] == "note"


def test_merge_equal_timestamp_tags_and_custom_fields_union():
    base = {
        "schema_version": 4,
        "entries": {
            "5": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 500,
                "tags": ["prod"],
                "custom_fields": [{"name": "owner", "value": "ops"}],
            }
        },
    }
    incoming = {
        "schema_version": 4,
        "entries": {
            "5": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 500,
                "tags": ["critical", "prod"],
                "custom_fields": [{"name": "env", "value": "us-east-1"}],
            }
        },
    }
    merged = merge_index_payloads(base, incoming, source_tag="b")
    entry = merged["entries"]["5"]
    assert entry["tags"] == ["critical", "prod"]
    assert entry["custom_fields"] == [
        {"name": "env", "value": "us-east-1"},
        {"name": "owner", "value": "ops"},
    ]


def test_merge_tombstone_removes_older_entry():
    current = {
        "schema_version": 4,
        "entries": {
            "2": {
                "kind": "password",
                "label": "x",
                "modified_ts": 100,
                "username": "alive",
            }
        },
    }
    incoming = {
        "schema_version": 4,
        "entries": {},
        "_sync_meta": {
            "tombstones": {
                "2": {
                    "deleted_ts": 101,
                    "entry_hash": "abc",
                    "event_hash": "f" * 64,
                }
            }
        },
    }
    merged = merge_index_payloads(current, incoming, source_tag="b")
    assert "2" not in merged["entries"]
    assert merged["_sync_meta"]["tombstones"]["2"]["deleted_ts"] == 101


def test_merge_tombstone_order_independent():
    base = {
        "schema_version": 4,
        "entries": {"1": {"kind": "password", "label": "x", "modified_ts": 9}},
    }
    a = {
        "schema_version": 4,
        "entries": {},
        "_sync_meta": {
            "tombstones": {
                "1": {
                    "deleted_ts": 10,
                    "entry_hash": "a",
                    "event_hash": "e" * 64,
                }
            }
        },
    }
    b = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "new",
                "modified_ts": 10,
                "username": "u",
            }
        },
    }
    ab = merge_index_payloads(
        merge_index_payloads(base, a, source_tag="a"), b, source_tag="b"
    )
    ba = merge_index_payloads(
        merge_index_payloads(base, b, source_tag="b"), a, source_tag="a"
    )
    assert ab["entries"] == ba["entries"]
    assert ab["_sync_meta"]["tombstones"] == ba["_sync_meta"]["tombstones"]


def test_merge_replay_same_payload_is_idempotent():
    base = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 10,
                "username": "",
            }
        },
    }
    incoming = {
        "schema_version": 4,
        "entries": {
            "1": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 11,
                "username": "alice",
            }
        },
        "_sync_meta": {"last_merge_ts": 11},
    }
    once = merge_index_payloads(base, incoming, source_tag="peer-a")
    twice = merge_index_payloads(once, incoming, source_tag="peer-a")
    assert once == twice


def test_merge_replay_older_payload_does_not_override_newer():
    current = {
        "schema_version": 4,
        "entries": {
            "9": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 50,
                "username": "new",
            }
        },
        "_sync_meta": {"last_merge_ts": 50},
    }
    stale = {
        "schema_version": 4,
        "entries": {
            "9": {
                "kind": "password",
                "label": "svc",
                "modified_ts": 40,
                "username": "old",
            }
        },
        "_sync_meta": {"last_merge_ts": 40},
    }
    merged = merge_index_payloads(current, stale, source_tag="peer-b")
    assert merged["entries"]["9"]["username"] == "new"
    assert merged["_sync_meta"]["last_merge_ts"] == 50


def test_merge_tombstone_replay_keeps_older_readd_deleted():
    current = {
        "schema_version": 4,
        "entries": {},
        "_sync_meta": {
            "last_merge_ts": 70,
            "tombstones": {"3": {"deleted_ts": 70, "event_hash": "d" * 64}},
        },
    }
    stale_readd = {
        "schema_version": 4,
        "entries": {
            "3": {
                "kind": "password",
                "label": "x",
                "modified_ts": 69,
                "username": "stale",
            }
        },
        "_sync_meta": {"last_merge_ts": 69},
    }
    merged = merge_index_payloads(current, stale_readd, source_tag="peer-c")
    assert "3" not in merged["entries"]
    assert merged["_sync_meta"]["tombstones"]["3"]["deleted_ts"] == 70


def test_merge_tombstone_allows_newer_recreate():
    current = {
        "schema_version": 4,
        "entries": {},
        "_sync_meta": {
            "last_merge_ts": 70,
            "tombstones": {"3": {"deleted_ts": 70, "event_hash": "d" * 64}},
        },
    }
    newer_readd = {
        "schema_version": 4,
        "entries": {
            "3": {
                "kind": "password",
                "label": "x",
                "modified_ts": 71,
                "username": "new",
            }
        },
        "_sync_meta": {"last_merge_ts": 71},
    }
    merged = merge_index_payloads(current, newer_readd, source_tag="peer-d")
    assert merged["entries"]["3"]["username"] == "new"
    assert "3" not in merged["_sync_meta"]["tombstones"]
    assert merged["_sync_meta"]["last_merge_ts"] == 71


def test_merge_last_merge_ts_order_independent():
    base = {
        "schema_version": 4,
        "entries": {
            "1": {"kind": "password", "label": "a", "modified_ts": 90},
        },
        "_sync_meta": {"last_merge_ts": 90},
    }
    a = {
        "schema_version": 4,
        "entries": {
            "1": {"kind": "password", "label": "a", "modified_ts": 100},
        },
        "_sync_meta": {"last_merge_ts": 100},
    }
    b = {
        "schema_version": 4,
        "entries": {},
        "_sync_meta": {
            "last_merge_ts": 95,
            "tombstones": {"2": {"deleted_ts": 95, "event_hash": "a" * 64}},
        },
    }
    ab = merge_index_payloads(
        merge_index_payloads(base, a, source_tag="a"), b, source_tag="b"
    )
    ba = merge_index_payloads(
        merge_index_payloads(base, b, source_tag="b"), a, source_tag="a"
    )
    assert ab["_sync_meta"]["last_merge_ts"] == ba["_sync_meta"]["last_merge_ts"] == 100
