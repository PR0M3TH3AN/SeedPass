import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def setup_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    backup = BackupManager(tmp_path, cfg)
    return EntryManager(vault, backup)


def test_modify_ssh_entry():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_mgr(tmp_path)

        idx = em.add_ssh_key("ssh", TEST_SEED)
        em.modify_entry(idx, label="newssh", notes="n", archived=True, tags=["x"])
        entry = em.retrieve_entry(idx)

        assert entry["label"] == "newssh"
        assert entry["notes"] == "n"
        assert entry["archived"] is True
        assert entry["tags"] == ["x"]


def test_modify_managed_account_entry():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_mgr(tmp_path)

        idx = em.add_managed_account("acct", TEST_SEED)
        em.modify_entry(
            idx,
            label="acct2",
            value="val",
            notes="note",
            archived=True,
            tags=["tag"],
        )
        entry = em.retrieve_entry(idx)

        assert entry["label"] == "acct2"
        assert entry["value"] == "val"
        assert entry["notes"] == "note"
        assert entry["archived"] is True
        assert entry["tags"] == ["tag"]
