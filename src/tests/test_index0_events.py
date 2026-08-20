from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import TEST_PASSWORD, TEST_SEED, create_vault

from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.index0 import compute_head_hash


def _entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def _index0_for(em: EntryManager) -> dict:
    return em.vault.load_index()["_system"]["index0"]


def test_index0_emits_create_modify_archive_restore_delete_events():
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))

        idx = em.add_entry("example.com", 16, username="alice", tags=["ops"])
        em.modify_entry(idx, label="example.org", notes="updated")
        em.archive_entry(idx)
        em.restore_entry(idx)
        em.delete_entry(idx)

        index0 = _index0_for(em)
        events = list(index0["events"].values())
        event_types = [event["event_type"] for event in events]

        assert event_types == [
            "entry_created",
            "entry_modified",
            "entry_archived",
            "entry_restored",
            "entry_deleted",
        ]
        assert all(event["subject_id"] == str(idx) for event in events)
        assert events[0]["writer_id"] == f"writer:profile:{Path(tmpdir).name}"
        assert events[0]["scope_path"] == f"seed/{Path(tmpdir).name}"
        assert index0["stats"]["event_count"] == 5
        assert (
            index0["heads"][events[-1]["writer_id"]]["event_id"]
            == events[-1]["event_id"]
        )
        assert events[1]["prev_hash"] == compute_head_hash(events[0])
        assert events[2]["prev_hash"] == compute_head_hash(events[1])
        assert events[3]["prev_hash"] == compute_head_hash(events[2])
        assert events[4]["prev_hash"] == compute_head_hash(events[3])


def test_index0_emits_link_add_and_remove_events():
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))

        src = em.add_document("Project Plan", "v1", file_type="md")
        dst = em.add_key_value("API Token", "token", "abc")
        em.add_link(src, dst, relation="references", note="used by deploy")
        em.remove_link(src, dst, relation="references")

        index0 = _index0_for(em)
        link_events = [
            event
            for event in index0["events"].values()
            if event["event_type"] in {"link_added", "link_removed"}
        ]

        assert [event["event_type"] for event in link_events] == [
            "link_added",
            "link_removed",
        ]
        assert link_events[0]["links"] == [
            {"target_id": str(dst), "relation": "references", "note": "used by deploy"}
        ]
        assert link_events[1]["payload_ref"]["target_id"] == str(dst)


def test_index0_managed_account_scope_uses_hierarchy_path():
    with TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir)
        managed_dir = root_dir / "accounts" / "child-fp"
        managed_dir.mkdir(parents=True, exist_ok=True)
        em = _entry_manager(managed_dir)

        idx = em.add_document("Managed Doc", "body")

        index0 = _index0_for(em)
        event = next(iter(index0["events"].values()))

        assert event["subject_id"] == str(idx)
        assert event["writer_id"] == "writer:profile:child-fp"
        assert event["scope_path"] == f"seed/{root_dir.name}/managed/child-fp"
