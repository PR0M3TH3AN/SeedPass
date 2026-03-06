import json
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import TEST_PASSWORD, TEST_SEED, create_vault

from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.index0 import (
    INDEX0_MAX_CHECKPOINTS_PER_WRITER,
    build_manifest_index0_metadata,
    compact_index0_payload,
    compute_head_hash,
    derive_index0_context,
    make_index0_event,
)
from seedpass.core.manager import EncryptionMode, PasswordManager


def _entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_compact_index0_payload_builds_daily_checkpoints_and_manifest_metadata():
    payload = {"schema_version": 4, "entries": {}, "_system": {"index0": {}}}
    context = derive_index0_context("root-fp")
    event_day1 = make_index0_event(
        event_type="entry_created",
        subject_type="entry",
        subject_id="1",
        subject_kind="document",
        modified_ts=1709251200,
        writer_id=context["writer_id"],
        actor_id=context["actor_id"],
        scope_path=context["scope_path"],
        payload_ref={"entry_id": "1"},
        source="test",
    )
    event_day2 = make_index0_event(
        event_type="entry_modified",
        subject_type="entry",
        subject_id="1",
        subject_kind="document",
        modified_ts=1709337600,
        writer_id=context["writer_id"],
        actor_id=context["actor_id"],
        scope_path=context["scope_path"],
        prev_hash=compute_head_hash(event_day1),
        payload_ref={"entry_id": "1"},
        source="test",
    )
    payload["_system"]["index0"] = {
        "events": {
            event_day1["event_id"]: event_day1,
            event_day2["event_id"]: event_day2,
        },
        "heads": {
            context["writer_id"]: {
                "event_id": event_day2["event_id"],
                "head_hash": compute_head_hash(event_day2),
                "modified_ts": event_day2["modified_ts"],
            }
        },
    }

    compacted = compact_index0_payload(payload)
    checkpoints = compacted["_system"]["index0"]["checkpoints"]

    assert sorted(checkpoints) == [
        f"cp:day:2024-03-01:{context['writer_id']}",
        f"cp:day:2024-03-02:{context['writer_id']}",
    ]
    assert checkpoints[f"cp:day:2024-03-02:{context['writer_id']}"][
        "head_hash"
    ] == compute_head_hash(event_day2)

    metadata = build_manifest_index0_metadata(compacted)
    assert metadata["schema_version"] == 1
    assert metadata["checkpoint_ids"][0] == f"cp:day:2024-03-02:{context['writer_id']}"
    assert metadata["stream_heads"][context["writer_id"]] == compute_head_hash(
        event_day2
    )


def test_compact_index0_payload_applies_checkpoint_retention_per_writer():
    payload = {"schema_version": 4, "entries": {}, "_system": {"index0": {}}}
    context = derive_index0_context("root-fp")
    events = {}
    prev_hash = ""
    for day in range(1, INDEX0_MAX_CHECKPOINTS_PER_WRITER + 6):
        ts = 1704067200 + (day * 86400)
        event = make_index0_event(
            event_type="entry_modified",
            subject_type="entry",
            subject_id=str(day),
            subject_kind="document",
            modified_ts=ts,
            writer_id=context["writer_id"],
            actor_id=context["actor_id"],
            scope_path=context["scope_path"],
            prev_hash=prev_hash,
            payload_ref={"entry_id": str(day)},
            source="test",
        )
        prev_hash = compute_head_hash(event)
        events[event["event_id"]] = event
    payload["_system"]["index0"] = {
        "events": events,
        "heads": {
            context["writer_id"]: {
                "event_id": event["event_id"],
                "head_hash": prev_hash,
                "modified_ts": event["modified_ts"],
            }
        },
    }

    compacted = compact_index0_payload(payload)
    checkpoints = compacted["_system"]["index0"]["checkpoints"]

    assert len(checkpoints) == INDEX0_MAX_CHECKPOINTS_PER_WRITER
    assert f"cp:day:2024-01-02:{context['writer_id']}" not in checkpoints


def test_sync_vault_publishes_manifest_index0_metadata(dummy_nostr_client):
    client, relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        fp_dir = Path(tmpdir)
        vault, enc_mgr = create_vault(fp_dir)
        cfg_mgr = ConfigManager(vault, fp_dir)
        backup_mgr = BackupManager(fp_dir, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.config_manager = cfg_mgr
        pm.nostr_client = client
        pm.fingerprint_dir = fp_dir
        pm.current_fingerprint = fp_dir.name
        pm.parent_seed = TEST_SEED
        pm.is_dirty = False
        pm.offline_mode = False
        pm.state_manager = None

        pm.entry_manager.add_entry("site", 8)
        result = pm.sync_vault()

        manifest_payload = json.loads(relay.manifests[-1].content())

        assert result is not None
        assert "index0" in manifest_payload
        assert manifest_payload["index0"]["schema_version"] == 1
        assert manifest_payload["index0"]["checkpoint_ids"]
        assert manifest_payload["index0"]["stream_heads"]
