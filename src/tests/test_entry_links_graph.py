import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_PASSWORD, TEST_SEED

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager


def _entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_links_add_list_remove_and_search():
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))
        src = em.add_document("Project Plan", "v1", file_type="md")
        dst = em.add_key_value("API Token", "token", "abc")

        links = em.add_link(src, dst, relation="references", note="used by deploy")
        assert links == [
            {"target_id": dst, "relation": "references", "note": "used by deploy"}
        ]

        resolved = em.get_links(src)
        assert resolved[0]["target_id"] == dst
        assert resolved[0]["relation"] == "references"
        assert resolved[0]["target_label"] == "API Token"
        assert resolved[0]["target_kind"] == "key_value"

        # Query by relation, note, and target label should match source.
        assert em.search_entries("references")[0][0] == src
        assert em.search_entries("deploy")[0][0] == src
        assert em.search_entries("api token")[0][0] == src

        remaining = em.remove_link(src, dst, relation="references")
        assert remaining == []
        assert em.get_links(src) == []


def test_links_reject_invalid_targets_and_self_link():
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))
        idx = em.add_entry("example", 12)

        try:
            em.add_link(idx, idx)
            assert False, "Expected self-link validation failure"
        except ValueError as exc:
            assert "Self-referential" in str(exc)

        try:
            em.add_link(idx, 9999)
            assert False, "Expected missing target validation failure"
        except ValueError as exc:
            assert "Target entry not found" in str(exc)
