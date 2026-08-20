from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import pytest

from helpers import TEST_PASSWORD, TEST_SEED, create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.portable_backup import export_backup, import_backup

pytestmark = pytest.mark.determinism


def _make_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def _make_managers(tmp_path: Path) -> tuple[EntryManager, BackupManager]:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr), backup_mgr


def _deterministic_text_bytes(size: int) -> str:
    """Return deterministic ASCII text of at least *size* bytes."""
    block = (
        "SeedPass deterministic document payload block. "
        "0123456789 abcdefghijklmnopqrstuvwxyz\n"
    )
    repeats = (size // len(block)) + 1
    text = block * repeats
    return text[:size]


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


@pytest.mark.parametrize("size_bytes", [1024, 512 * 1024, 1024 * 1024])
def test_import_export_large_document_roundtrip_is_byte_stable(size_bytes: int):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        entry_mgr = _make_entry_manager(base)
        content = _deterministic_text_bytes(size_bytes)
        source = base / "large_doc.md"
        source.write_text(content, encoding="utf-8")

        idx = entry_mgr.import_document_file(source, tags=["large", "determinism"])
        entry = entry_mgr.retrieve_entry(idx)
        assert entry is not None
        assert entry["file_type"] == "md"
        assert entry["content"] == content

        out_dir = base / "out"
        exported = entry_mgr.export_document_file(idx, output_path=out_dir)
        exported_content = exported.read_text(encoding="utf-8")
        assert exported_content == content
        assert (
            hashlib.sha256(exported_content.encode("utf-8")).hexdigest()
            == hashlib.sha256(content.encode("utf-8")).hexdigest()
        )


@pytest.mark.parametrize("encrypt", [True, False], ids=["encrypted", "plaintext"])
def test_portable_backup_restore_preserves_document_content_and_extension(
    encrypt: bool,
):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        entry_mgr, backup_mgr = _make_managers(base)
        content = _deterministic_text_bytes(256 * 1024)

        idx = entry_mgr.add_document(
            "Ops Runbook",
            content,
            file_type="py",
            notes="critical",
            tags=["ops", "runbook"],
        )
        before = entry_mgr.retrieve_entry(idx)
        assert before is not None

        export_path = base / "portable_export.json"
        export_backup(
            entry_mgr.vault,
            backup_mgr,
            export_path,
            parent_seed=TEST_SEED,
            encrypt=encrypt,
        )

        entry_mgr.modify_entry(
            idx,
            label="mutated",
            content="mutated content",
            file_type="txt",
            notes="changed",
            tags=["changed"],
        )

        import_backup(
            entry_mgr.vault,
            backup_mgr,
            export_path,
            parent_seed=TEST_SEED,
        )
        entry_mgr.clear_cache()
        after = entry_mgr.retrieve_entry(idx)
        assert after == before


def test_backup_manager_restore_latest_preserves_large_document_content():
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        entry_mgr, backup_mgr = _make_managers(base)
        content = _deterministic_text_bytes(300 * 1024)
        idx = entry_mgr.add_document("Design Doc", content, file_type="txt")
        before = entry_mgr.retrieve_entry(idx)
        assert before is not None

        backup_mgr.restore_latest_backup()
        restored = entry_mgr.retrieve_entry(idx)
        assert restored == before
