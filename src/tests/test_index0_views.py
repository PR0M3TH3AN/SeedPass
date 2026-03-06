from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import TEST_PASSWORD, TEST_SEED, create_vault

from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.index0 import (
    compact_index0_payload,
    derive_index0_context,
    get_canonical_view,
    list_canonical_views,
)


def _entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_compact_index0_payload_builds_default_canonical_views():
    with TemporaryDirectory() as tmpdir:
        path = Path(tmpdir)
        em = _entry_manager(path)
        doc_id = em.add_document("Project Plan", "v1", file_type="md", tags=["docs"])
        pw_id = em.add_entry("example.com", 12, username="alice")
        em.archive_entry(pw_id)
        payload = compact_index0_payload(em.vault.load_index(), fingerprint_dir=path)
        index0 = payload["_system"]["index0"]
        scope_path = derive_index0_context(path)["scope_path"]

        children = get_canonical_view(
            index0, view_type="children_of", scope_path=scope_path
        )
        counts = get_canonical_view(
            index0, view_type="counts_by_kind", scope_path=scope_path
        )
        recent = get_canonical_view(
            index0, view_type="recent_activity", scope_path=scope_path
        )

        assert children is not None
        assert counts is not None
        assert recent is not None
        assert [child["entry_id"] for child in children["data"]["children"]] == [
            str(doc_id),
            str(pw_id),
        ]
        assert counts["data"]["counts"]["document"] == 1
        assert counts["data"]["counts"]["password"] == 1
        assert counts["data"]["archived_count"] == 1
        assert "entry_archived" in [
            item["event_type"] for item in recent["data"]["items"]
        ]
        assert index0["view_manifest"]["canonical_view_types"] == [
            "children_of",
            "counts_by_kind",
            "recent_activity",
        ]


def test_list_canonical_views_returns_sorted_views():
    with TemporaryDirectory() as tmpdir:
        path = Path(tmpdir)
        em = _entry_manager(path)
        em.add_document("Doc", "body")
        index0 = em.vault.load_index()["_system"]["index0"]

        views = list_canonical_views(index0)

        assert [view["view_id"] for view in views] == sorted(
            view["view_id"] for view in views
        )
        assert len(views) == 3
