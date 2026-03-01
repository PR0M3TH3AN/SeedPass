from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import TEST_PASSWORD, TEST_SEED, create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager


def _make_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_import_document_file_roundtrip():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        entry_mgr = _make_entry_manager(base)
        source = base / "notes.md"
        source.write_text("# hello\nworld\n", encoding="utf-8")

        idx = entry_mgr.import_document_file(source, notes="imported", tags=["docs"])
        entry = entry_mgr.retrieve_entry(idx)
        assert entry is not None
        assert entry["kind"] == "document"
        assert entry["label"] == "notes"
        assert entry["file_type"] == "md"
        assert entry["content"] == "# hello\nworld\n"
        assert entry["notes"] == "imported"
        assert entry["tags"] == ["docs"]


def test_export_document_file_writes_expected_content():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        entry_mgr = _make_entry_manager(base)
        idx = entry_mgr.add_document("Runbook", "line1\nline2", file_type="txt")

        out_dir = base / "exports"
        dest = entry_mgr.export_document_file(idx, output_path=out_dir)
        assert dest.exists()
        assert dest.suffix == ".txt"
        assert dest.read_text(encoding="utf-8") == "line1\nline2"
