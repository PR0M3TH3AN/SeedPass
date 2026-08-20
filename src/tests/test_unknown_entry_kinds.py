"""Unknown-kind passthrough (spec section 8.2).

Python is the naturally tolerant implementation: it loads the index as plain
dicts and never validates entry kinds on the way through. That tolerance is
load-bearing for vault sharing -- a record written by another application
(e.g. a future BitLogin ``bitlogin_org``) must survive a Python
read-modify-write cycle untouched. This pins it so it cannot regress
silently.

``_normalize_entry_defaults`` deliberately skips foreign kinds: the legacy
renames it performs (website->label, blacklisted->archived) are migrations
for OUR old shapes, and applying them to another application's record would
mangle it. So the assertion here is exact equality -- untouched means
untouched, matching the TypeScript side byte for byte.
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

        # Allocation skipped past the foreign id, and the record is
        # byte-for-byte untouched -- no backfill, no legacy renames.
        assert int(new_id) == 2
        final = vault.load_index()
        assert final["entries"]["1"] == FOREIGN_RECORD


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
        assert final["entries"]["1"] == FOREIGN_RECORD
        assert final["entries"]["0"].get("archived") is True


def test_foreign_record_with_legacy_trap_fields_is_not_reinterpreted():
    """A foreign record carrying field names our legacy migrations act on
    (``blacklisted``, ``website``, ``words``) must NOT have them renamed or
    popped -- they mean whatever the other application says they mean."""
    trap = {
        "kind": "bitlogin_device",
        "type": "bitlogin_device",
        "label": "kiosk",
        "modified_ts": 1700000456,
        "blacklisted": "no, this is a hostname",
        "website": "not-our-alias",
        "words": ["arbitrary", "foreign", "list"],
    }
    with TemporaryDirectory() as tmpdir:
        vault, _enc = create_vault(Path(tmpdir))
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        entry_mgr.add_entry("native", 12)
        data = vault.load_index()
        data["entries"]["1"] = dict(trap)
        vault.save_index(data)

        entry_mgr2 = EntryManager(vault, backup_mgr)
        entry_mgr2.add_entry("native-2", 12)
        assert vault.load_index()["entries"]["1"] == trap
