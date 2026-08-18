"""Unknown-kind passthrough (spec section 8.2).

Python is the naturally tolerant implementation: it loads the index as plain
dicts and never validates entry kinds on the way through. That tolerance is
load-bearing for vault sharing -- a record written by another application
(e.g. a future BitLogin ``bitlogin_org``) must survive a Python
read-modify-write cycle untouched. This pins it so it cannot regress
silently.

One nuance, discovered by this test: Python's ``_load_index`` backfills the
spec's base-field defaults (``tags``, ``links``, ``date_modified``) onto
every entry, foreign ones included. That adds spec-defined fields with
neutral values -- no foreign data is lost or altered, which is what
preservation actually protects. The assertions therefore check that every
foreign field survives with its exact value, not dict equality. (TypeScript
carries foreign records verbatim without the backfill; that divergence is
recorded in the spec's gap ledger and matters once foreign kinds sync.)
"""

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.append(str(Path(__file__).resolve().parents[1]))

from helpers import create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager

FOREIGN_RECORD = {
    "kind": "bitlogin_org",
    "type": "bitlogin_org",
    "label": "Acme Corporation",
    "modified_ts": 1700000123,
    "bitlogin": {
        "admins": ["npub1aaaa"],
        "roles": {"sales": ["npub1bbbb"]},
        "policy_rev": 7,
    },
}


def test_foreign_record_survives_read_modify_write():
    with TemporaryDirectory() as tmpdir:
        vault, _enc = create_vault(Path(tmpdir))
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        # Seed the vault, then plant a foreign record beside a native one.
        entry_mgr.add_entry("native", 12)  # id 0
        data = vault.load_index()
        data["entries"]["1"] = dict(FOREIGN_RECORD)
        vault.save_index(data)

        # A fresh manager performs an ordinary mutation next to it.
        entry_mgr2 = EntryManager(vault, backup_mgr)
        new_id = entry_mgr2.add_entry("native-2", 12)

        # Allocation skipped past the foreign id, and every foreign field
        # survived with its exact value (base-field backfill is permitted).
        assert int(new_id) == 2
        final = vault.load_index()
        stored = final["entries"]["1"]
        for key, value in FOREIGN_RECORD.items():
            assert stored[key] == value


def test_foreign_record_survives_archive_of_neighbour():
    with TemporaryDirectory() as tmpdir:
        vault, _enc = create_vault(Path(tmpdir))
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        entry_mgr.add_entry("native", 12)  # id 0
        data = vault.load_index()
        data["entries"]["1"] = dict(FOREIGN_RECORD)
        vault.save_index(data)

        entry_mgr2 = EntryManager(vault, backup_mgr)
        entry_mgr2.archive_entry(0)

        final = vault.load_index()
        stored = final["entries"]["1"]
        for key, value in FOREIGN_RECORD.items():
            assert stored[key] == value
        assert final["entries"]["0"].get("archived") is True
