from __future__ import annotations
import pytest

pytest.importorskip("textual")
from unittest.mock import MagicMock
from textual.widgets import DataTable
from seedpass.tui_v3.app import SeedPassTuiV3


class MockEntryService:
    def __init__(self):
        self.entries = {
            1: {
                "id": 1,
                "label": "test-pwd",
                "kind": "password",
                "username": "user1",
                "length": 16,
            },
            2: {"id": 2, "label": "test-ssh", "kind": "ssh", "index": 0},
            3: {"id": 3, "label": "test-pgp", "kind": "pgp", "index": 0},
            4: {"id": 4, "label": "test-nostr", "kind": "nostr", "index": 0},
            5: {
                "id": 5,
                "label": "test-doc",
                "kind": "document",
                "content": "hello world",
            },
            6: {"id": 6, "label": "test-seed", "kind": "seed", "index": 0},
        }

    def search_entries(
        self, query="", kinds=None, include_archived=False, archived_only=False
    ):
        results = []
        for e in self.entries.values():
            kind = e["kind"]
            if kinds and kind not in kinds:
                continue
            is_arch = e.get("archived", False)
            if archived_only and not is_arch:
                continue
            if not include_archived and is_arch:
                continue
            results.append(
                (
                    e["id"],
                    e["label"],
                    e.get("username"),
                    e.get("url"),
                    is_arch,
                    MagicMock(value=kind),
                )
            )
        return results

    def retrieve_entry(self, eid):
        return self.entries.get(eid)

    def generate_password(self, length, eid):
        return "gen-pwd"

    def get_ssh_key_pair(self, eid):
        return "priv", "pub"

    def get_pgp_key(self, eid):
        return "priv", "pub", "fp"

    def get_nostr_key_pair(self, eid):
        return "npub", "nsec"

    def get_seed_phrase(self, eid, parent):
        return "word1 word2"

    def copy_to_clipboard(self, val):
        return True

    def archive_entry(self, eid):
        self.entries[eid]["archived"] = True

    def restore_entry(self, eid):
        self.entries[eid]["archived"] = False

    def load_managed_account(self, eid):
        pass

    def exit_managed_account(self):
        pass

    def add_entry(self, label, username=None, url=None, length=16, tags=None):
        eid = max(self.entries.keys()) + 1
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "password",
            "username": username,
            "tags": tags,
        }
        return eid

    def add_totp(self, label, secret, username=None, tags=None):
        eid = max(self.entries.keys()) + 1
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "totp",
            "username": username,
            "tags": tags,
        }
        return eid

    def add_seed(self, label, index=0, tags=None):
        eid = max(self.entries.keys()) + 1
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "seed",
            "index": index,
            "tags": tags,
        }
        return eid

    def add_managed_account(self, label, index=0, tags=None):
        eid = max(self.entries.keys()) + 1
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "managed_account",
            "index": index,
            "tags": tags,
        }
        return eid


class LegacyPgpEntryService(MockEntryService):
    def get_pgp_key(self, eid):
        _ = eid
        return "legacy-priv", "legacy-pub"


class SeedArgCompatEntryService(MockEntryService):
    def __init__(self):
        super().__init__()
        self.entries[7] = {"id": 7, "label": "seed-compat", "kind": "seed", "index": 0}

    def get_seed_phrase(self, eid):
        _ = eid
        return "abandon ability able about"


class MockVaultService:
    def __init__(self):
        self._manager = MagicMock()
        self._manager.current_fingerprint = "parent-fp"
        self._manager.profile_stack = []

    def stats(self):
        return {
            "total_entries": (
                len(self._manager.entries) if hasattr(self._manager, "entries") else 6
            )
        }


@pytest.mark.anyio
async def test_v3_reveal_copy_parity():
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        app.selected_entry_id = 1
        app.action_reveal_selected(confirm=True)
        payload = app._resolve_sensitive_payload()
        assert payload[3] == "gen-pwd"
        app.selected_entry_id = 4
        payload = app._resolve_sensitive_payload()
        assert payload[3] == "nsec"


@pytest.mark.anyio
async def test_v3_archive_restore():
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        app.selected_entry_id = 1
        app.action_toggle_archive()
        assert app.services["entry"].entries[1].get("archived") is True
        app.action_toggle_archive()
        assert app.services["entry"].entries[1].get("archived") is False


@pytest.mark.anyio
async def test_v3_add_entry():
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        app.action_add_entry()
        await pilot.pause()
        screen = app.screen
        from textual.widgets import Input

        screen.query_one("#entry-label", Input).value = "New Password"
        screen.query_one("#entry-username", Input).value = "user@example.com"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert any(
            e["label"] == "New Password" for e in app.services["entry"].entries.values()
        )


@pytest.mark.anyio
async def test_v3_filters():
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#entry-data-table", DataTable)
        initial_count = table.row_count
        app.action_set_kind_filter("2fa")
        await pilot.pause()
        assert table.row_count == 0  # No TOTP in mock
        app.action_set_kind_filter("keys")
        await pilot.pause()
        assert table.row_count > 0


@pytest.mark.anyio
async def test_v3_pgp_payload_accepts_legacy_two_tuple() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: LegacyPgpEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        app.selected_entry_id = 3
        payload = app._resolve_sensitive_payload()
        assert payload[1] == "legacy-priv"
        assert payload[2] == "legacy-pub"
        assert payload[3] == "legacy-pub"


@pytest.mark.anyio
async def test_v3_seed_payload_accepts_single_arg_seed_getter() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: SeedArgCompatEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        app.selected_entry_id = 7
        payload = app._resolve_sensitive_payload()
        assert payload[0] == "Seed Words Revealed"
        assert payload[1] == "abandon ability able about"
