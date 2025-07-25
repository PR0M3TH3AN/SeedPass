from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from helpers import create_vault
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


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
        delta_a = va.get_encrypted_index() or b""
        vb.decrypt_and_save_index_from_nostr(delta_a, merge=True)
        emb.clear_cache()
        assert emb.retrieve_entry(idx0)["username"] == "ua"

        emb.modify_entry(idx1, username="ub")
        delta_b = vb.get_encrypted_index() or b""
        va.decrypt_and_save_index_from_nostr(delta_b, merge=True)
        ema.clear_cache()
        assert ema.retrieve_entry(idx1)["username"] == "ub"

        assert ema.retrieve_entry(idx0)["username"] == "ua"
        assert ema.retrieve_entry(idx1)["username"] == "ub"
        assert emb.retrieve_entry(idx0)["username"] == "ua"
        assert emb.retrieve_entry(idx1)["username"] == "ub"
