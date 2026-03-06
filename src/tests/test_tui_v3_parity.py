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


# ---------------------------------------------------------------------------
# Parity tests: legacy utility/maintenance commands migrated to v3
# ---------------------------------------------------------------------------


def _make_full_app(**extra_services):
    """Build a SeedPassTuiV3 with all mock services wired up."""
    entry_svc = MockEntryService()
    vault_svc = MockVaultService()
    utility_svc = MockUtilityService()
    sync_svc = MockSyncService()
    nostr_svc = MockNostrService()
    config_svc = MockConfigService()

    app = SeedPassTuiV3(
        entry_service_factory=lambda: entry_svc,
        vault_service_factory=lambda: vault_svc,
        utility_service_factory=lambda: utility_svc,
        sync_service_factory=lambda: sync_svc,
        nostr_service_factory=lambda: nostr_svc,
        config_service_factory=lambda: config_svc,
    )
    return app, entry_svc, vault_svc, utility_svc, sync_svc, nostr_svc, config_svc


@pytest.mark.anyio
async def test_v3_checksum_commands() -> None:
    app, *_, utility_svc, _, _, _ = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_checksum_verify()
        assert utility_svc.checksum_verified is True

        app.action_checksum_update()
        assert utility_svc.checksum_updated is True


@pytest.mark.anyio
async def test_v3_totp_export_no_path() -> None:
    app, entry_svc, *_ = _make_full_app()
    # Provide a basic export_totp_entries method
    entry_svc.export_totp_entries = lambda: {"1": "otpauth://totp/label?secret=ABC"}
    async with app.run_test() as pilot:
        await pilot.pause()
        # Should not raise; notifies count
        app.action_totp_export(None)


@pytest.mark.anyio
async def test_v3_sync_commands() -> None:
    app, _, _, _, sync_svc, _, _ = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_sync_now()
        assert sync_svc.synced is True

        app.action_sync_bg()
        assert sync_svc.bg_synced is True


@pytest.mark.anyio
async def test_v3_relay_commands() -> None:
    app, _, _, _, _, nostr_svc, _ = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        app.action_relay_add("wss://new.relay")
        assert "wss://new.relay" in nostr_svc.added

        app.action_relay_rm(0)
        assert 0 in nostr_svc.removed

        app.action_relay_reset()
        assert nostr_svc.reset_called is True


@pytest.mark.anyio
async def test_v3_setting_secret() -> None:
    app, _, _, _, _, _, config_svc = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_setting_secret("on")
        assert config_svc.secret_mode_calls[-1][0] is True

        app.action_setting_secret("off")
        assert config_svc.secret_mode_calls[-1][0] is False


@pytest.mark.anyio
async def test_v3_setting_offline() -> None:
    app, _, _, _, _, _, config_svc = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_setting_offline("on")
        assert config_svc.offline_mode_calls[-1] is True

        app.action_setting_offline("off")
        assert config_svc.offline_mode_calls[-1] is False


@pytest.mark.anyio
async def test_v3_setting_config_keys() -> None:
    app, _, _, _, _, _, config_svc = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_setting_quick_unlock("on")
        assert config_svc._cfg.get("quick_unlock") == "on"

        app.action_setting_timeout("600")
        assert config_svc._cfg.get("inactivity_timeout") == "600"

        app.action_setting_kdf_mode("argon2id")
        assert config_svc._cfg.get("kdf_mode") == "argon2id"

        app.action_setting_kdf_iterations("200000")
        assert config_svc._cfg.get("kdf_iterations") == "200000"


@pytest.mark.anyio
async def test_v3_archive_filter() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()

        app.action_archive_filter("active")
        assert app.show_archived is False
        assert app.filter_archived_only is False

        app.action_archive_filter("all")
        assert app.show_archived is True
        assert app.filter_archived_only is False

        app.action_archive_filter("archived")
        assert app.show_archived is True
        assert app.filter_archived_only is True


@pytest.mark.anyio
async def test_v3_density() -> None:
    app = SeedPassTuiV3(
        entry_service_factory=lambda: MockEntryService(),
        vault_service_factory=lambda: MockVaultService(),
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_set_density("compact")
        assert app.density_mode == "compact"

        app.action_set_density("comfortable")
        assert app.density_mode == "comfortable"


@pytest.mark.anyio
async def test_v3_command_processor_routes_utility_commands() -> None:
    """Verify the CommandProcessor correctly routes new utility commands."""
    app, *_, utility_svc, sync_svc, nostr_svc, _ = _make_full_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        proc = app.processor

        proc.execute("checksum-verify")
        assert utility_svc.checksum_verified is True

        proc.execute("sync-now")
        assert sync_svc.synced is True

        proc.execute("relay-add wss://proc.relay")
        assert "wss://proc.relay" in nostr_svc.added

        proc.execute("archive-filter archived")
        assert app.show_archived is True
        assert app.filter_archived_only is True

        proc.execute("density compact")
        assert app.density_mode == "compact"
