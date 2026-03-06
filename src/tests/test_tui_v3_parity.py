from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from rich.text import Text
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

    def delete_entry(self, eid):
        self.entries.pop(eid, None)

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


class MockUtilityService:
    def __init__(self):
        self.checksum_verified = False
        self.checksum_updated = False

    def verify_checksum(self):
        self.checksum_verified = True

    def update_checksum(self):
        self.checksum_updated = True


class MockSyncService:
    def __init__(self):
        self.synced = False
        self.bg_synced = False

    def sync(self):
        self.synced = True
        return {"events": 1}

    def start_background_vault_sync(self, summary=None):
        self.bg_synced = True


class MockNostrService:
    def __init__(self):
        self.relays: list[str] = ["wss://relay.example.com"]
        self.added: list[str] = []
        self.removed: list[int] = []
        self.reset_called = False

    def add_relay(self, url: str):
        self.added.append(url)
        self.relays.append(url)

    def remove_relay(self, idx: int):
        self.removed.append(idx)

    def reset_relays(self) -> list[str]:
        self.reset_called = True
        self.relays = ["wss://default.relay"]
        return list(self.relays)


class MockConfigService:
    def __init__(self):
        self._cfg: dict = {}
        self.secret_mode_calls: list[tuple] = []
        self.offline_mode_calls: list[bool] = []

    def get(self, key: str):
        return self._cfg.get(key)

    def set(self, key: str, value: str):
        self._cfg[key] = value

    def get_clipboard_clear_delay(self) -> int:
        return 30

    def set_secret_mode(self, enabled: bool, delay: int):
        self.secret_mode_calls.append((enabled, delay))

    def set_offline_mode(self, enabled: bool):
        self.offline_mode_calls.append(enabled)


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


@pytest.mark.anyio
async def test_v3_action_bar_labels_include_leading_hotkey_letters() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        bar = app.screen.query_one("#action-bar")
        rendered = Text.from_markup(bar.render()).plain
        assert "Settings" in rendered
        assert "Add New Entry" in rendered
        assert "Create New Seed" in rendered
        assert "Remove Seed" in rendered
        assert "Export Data" in rendered
        assert "Import Data" in rendered
        assert "Backup Data" in rendered


@pytest.mark.anyio
async def test_v3_action_bar_global_row_uses_correct_handlers() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        bar = app.screen.query_one("#action-bar")
        markup = bar.render()
        # Backup Data must route to open_backup_parent_seed (has its own screen)
        assert "open_backup_parent_seed" in markup
        # Remove Seed must route to open_profile_management (not open_palette)
        assert "open_profile_management" in markup
        # Export/Import Data use open_palette because they need a path argument
        # Verify both labels still present
        from rich.text import Text
        rendered = Text.from_markup(markup).plain
        assert "Export Data" in rendered
        assert "Import Data" in rendered
        assert "Backup Data" in rendered
        assert "Remove Seed" in rendered


@pytest.mark.anyio
async def test_v3_action_bar_only_shows_context_actions_for_selected_kind() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        bar = app.screen.query_one("#action-bar")

        app.selected_entry_id = 5
        await pilot.pause()
        rendered = Text.from_markup(bar.render()).plain.splitlines()[1]
        assert "Context (document):" in rendered
        assert "Edit" in rendered
        assert "Export" in rendered
        assert "Copy" in rendered
        assert "Delete" in rendered
        assert "Reveal" not in rendered
        assert " QR" not in rendered
        assert "Load" not in rendered

        app.selected_entry_id = 6
        await pilot.pause()
        rendered = Text.from_markup(bar.render()).plain.splitlines()[1]
        assert "Context (seed):" in rendered
        assert "Reveal" in rendered
        assert "QR" in rendered
        assert "Load" in rendered
        assert "Delete" in rendered
        assert "Export" not in rendered


@pytest.mark.anyio
async def test_v3_action_bar_managed_account_excludes_qr() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    # Inject a managed_account entry into the mock service
    async with app.run_test() as pilot:
        await pilot.pause()
        app.services["entry"].entries[99] = {
            "id": 99,
            "label": "test-managed",
            "kind": "managed_account",
            "index": 0,
        }
        bar = app.screen.query_one("#action-bar")

        app.selected_entry_id = 99
        await pilot.pause()
        rendered = Text.from_markup(bar.render()).plain.splitlines()[1]
        assert "Context (managed_account):" in rendered
        assert "Reveal" in rendered
        assert "Load" in rendered
        assert "Delete" in rendered
        assert " QR" not in rendered
