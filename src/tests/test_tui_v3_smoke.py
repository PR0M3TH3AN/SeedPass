from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import DataTable, Input

from seedpass.tui_v3 import launch_tui3
from seedpass.tui_v3.app import (
    CreateProfileScreen,
    RecoverProfileScreen,
    SeedPassTuiV3,
    SeedWordsScreen,
    SeedWordsReviewScreen,
    StartupScreen,
)


class V3EntryService:
    def __init__(self) -> None:
        self._entries: dict[int, dict] = {
            1: {"id": 1, "kind": "password", "label": "Email", "length": 16},
            2: {"id": 2, "kind": "managed_account", "label": "Managed Ops"},
            3: {"id": 3, "kind": "nostr", "label": "Agent Nostr"},
        }
        self.copied: list[str] = []

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ):
        _ = (include_archived, archived_only)
        q = (query or "").strip().lower()
        rows = []
        for entry_id in sorted(self._entries.keys()):
            entry = self._entries[entry_id]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            rows.append(
                (
                    entry_id,
                    label,
                    entry.get("username"),
                    entry.get("url"),
                    bool(entry.get("archived", False)),
                    SimpleNamespace(value=kind),
                )
            )
        return rows

    def retrieve_entry(self, entry_id: int):
        return dict(self._entries.get(int(entry_id), {}))

    def generate_password(self, length: int, entry_id: int) -> str:
        return f"pw-{entry_id}-{length}"

    def archive_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = False

    def copy_to_clipboard(self, value: str) -> bool:
        self.copied.append(value)
        return True


class V3ProfileService:
    def list_profiles(self) -> list[str]:
        return ["EFBE51E70ED1B53A"]


class V3VaultService:
    def __init__(self) -> None:
        self.locked = False
        self.last_unlock_password: str | None = None
        self._manager = SimpleNamespace(parent_seed="PARENT_SEED")

    def lock(self) -> None:
        self.locked = True

    def unlock(self, request) -> SimpleNamespace:
        if hasattr(request, "password"):
            self.last_unlock_password = str(request.password)
        else:
            self.last_unlock_password = str(request)
        self.locked = False
        return SimpleNamespace(status="ok", duration=0.01)

    def stats(self) -> dict[str, int]:
        return {"total_entries": 3}


def _build_app() -> tuple[object, V3EntryService, V3VaultService]:
    holder: dict[str, object] = {}
    entry = V3EntryService()
    vault = V3VaultService()
    profile = V3ProfileService()

    def _hook(app):
        holder["app"] = app

    launched = launch_tui3(
        fingerprint="EFBE51E70ED1B53A",
        entry_service_factory=lambda: entry,
        profile_service_factory=lambda: profile,
        vault_service_factory=lambda: vault,
        app_hook=_hook,
    )
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app, entry, vault


@pytest.mark.anyio
async def test_tui3_palette_lock_unlock_and_session_status() -> None:
    app, _entry, vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.session_locked is False
        app.processor.execute("session-status")
        app.processor.execute("lock")
        await pilot.pause()
        assert app.session_locked is True
        assert vault.locked is True
        assert isinstance(app.screen, StartupScreen)
        app.processor.execute("unlock hunter2")
        await pilot.pause()
        assert app.session_locked is False
        assert vault.locked is False
        assert vault.last_unlock_password == "hunter2"


@pytest.mark.anyio
async def test_tui3_sidebar_child_nodes_open_entries() -> None:
    app, _entry, _vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        tree = app.screen.query_one("#profile-tree")
        tree.on_tree_node_selected(
            SimpleNamespace(node=SimpleNamespace(data="managed:2"))
        )
        await pilot.pause()
        assert app.selected_entry_id == 2
        assert app.active_fingerprint == "EFBE51E70ED1B53A"
        tree.on_tree_node_selected(
            SimpleNamespace(node=SimpleNamespace(data="agent:3"))
        )
        await pilot.pause()
        assert app.selected_entry_id == 3


@pytest.mark.anyio
async def test_tui3_grid_focus_refresh_enables_selection_after_runtime_add() -> None:
    app, entry, _vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        entry._entries[4] = {
            "id": 4,
            "kind": "password",
            "label": "Runtime Added",
            "length": 18,
        }
        table = app.screen.query_one("#entry-data-table", DataTable)
        table.focus()
        await pilot.pause()
        table._refresh_data()
        await pilot.pause()
        assert table.row_count >= 4


@pytest.mark.anyio
async def test_tui3_starts_with_unlock_screen_when_services_are_not_preloaded() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: [
        {"fingerprint": "EFBE51E70ED1B53A", "label": "Primary (EFBE51E70ED1B53A)"}
    ]
    captured: dict[str, str] = {}

    def _bootstrap(fingerprint: str, password: str) -> None:
        captured["fingerprint"] = fingerprint
        captured["password"] = password

    app._bootstrap_profile_session = _bootstrap

    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, StartupScreen)
        assert app.screen.query_one("#startup-profile-choice", Input).value == "1"
        app.screen.query_one("#startup-password", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()
        assert captured == {
            "fingerprint": "EFBE51E70ED1B53A",
            "password": "hunter2",
        }


@pytest.mark.anyio
async def test_tui3_create_profile_screen_uses_in_app_bootstrap_helpers() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: []
    created: dict[str, str] = {}
    booted: dict[str, str] = {}

    def _create_existing_profile(*, seed: str, password: str) -> str:
        created["seed"] = seed
        created["password"] = password
        return "NEWFP123"

    def _bootstrap(fingerprint: str, password: str) -> None:
        booted["fingerprint"] = fingerprint
        booted["password"] = password

    app._create_existing_profile = _create_existing_profile
    app._bootstrap_profile_session = _bootstrap

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(CreateProfileScreen())
        await pilot.pause()
        screen = app.screen
        screen.query_one("#create-mode", Input).value = "existing"
        screen.query_one("#create-seed", Input).value = (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        screen.query_one("#create-password", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()
        assert created["password"] == "hunter2"
        assert booted == {"fingerprint": "NEWFP123", "password": "hunter2"}


@pytest.mark.anyio
async def test_tui3_recover_profile_screen_uses_in_app_bootstrap_helpers() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: [
        {"fingerprint": "EFBE51E70ED1B53A", "label": "Primary (EFBE51E70ED1B53A)"}
    ]
    recovered: dict[str, str] = {}
    booted: dict[str, str] = {}

    def _recover_profile(*, fingerprint: str, seed: str, password: str) -> None:
        recovered["fingerprint"] = fingerprint
        recovered["seed"] = seed
        recovered["password"] = password

    def _bootstrap(fingerprint: str, password: str) -> None:
        booted["fingerprint"] = fingerprint
        booted["password"] = password

    app._recover_profile = _recover_profile
    app._bootstrap_profile_session = _bootstrap

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(RecoverProfileScreen())
        await pilot.pause()
        screen = app.screen
        screen.query_one("#recover-choice", Input).value = "1"
        screen.query_one("#recover-seed", Input).value = (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        screen.query_one("#recover-password", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()
        assert recovered["fingerprint"] == "EFBE51E70ED1B53A"
        assert booted == {
            "fingerprint": "EFBE51E70ED1B53A",
            "password": "hunter2",
        }


@pytest.mark.anyio
async def test_tui3_create_profile_screen_supports_nostr_restore_mode() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: []
    restored: dict[str, object] = {}
    booted: dict[str, str] = {}

    def _restore_from_nostr_profile(
        *, seed: str, password: str, continue_without_backup: bool
    ) -> str:
        restored["seed"] = seed
        restored["password"] = password
        restored["continue_without_backup"] = continue_without_backup
        return "NOSTRFP1"

    def _bootstrap(fingerprint: str, password: str) -> None:
        booted["fingerprint"] = fingerprint
        booted["password"] = password

    app._restore_from_nostr_profile = _restore_from_nostr_profile
    app._bootstrap_profile_session = _bootstrap

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(CreateProfileScreen())
        await pilot.pause()
        screen = app.screen
        screen.query_one("#create-mode", Input).value = "nostr"
        screen.query_one("#create-seed", Input).value = (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        screen.query_one("#create-nostr-empty-ok", Input).value = "yes"
        screen.query_one("#create-password", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()
        assert restored["continue_without_backup"] is True
        assert booted == {"fingerprint": "NOSTRFP1", "password": "hunter2"}


@pytest.mark.anyio
async def test_tui3_create_profile_screen_supports_backup_restore_mode() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: []
    restored: dict[str, str] = {}
    booted: dict[str, str] = {}

    def _restore_from_backup_profile(
        *, seed: str, password: str, backup_path: str
    ) -> str:
        restored["seed"] = seed
        restored["password"] = password
        restored["backup_path"] = backup_path
        return "BACKUPFP1"

    def _bootstrap(fingerprint: str, password: str) -> None:
        booted["fingerprint"] = fingerprint
        booted["password"] = password

    app._restore_from_backup_profile = _restore_from_backup_profile
    app._bootstrap_profile_session = _bootstrap

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(CreateProfileScreen())
        await pilot.pause()
        screen = app.screen
        screen.query_one("#create-mode", Input).value = "backup"
        screen.query_one("#create-seed", Input).value = (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        screen.query_one("#create-backup-path", Input).value = "/tmp/profile-backup.enc"
        screen.query_one("#create-password", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()
        assert restored["backup_path"] == "/tmp/profile-backup.enc"
        assert booted == {"fingerprint": "BACKUPFP1", "password": "hunter2"}


@pytest.mark.anyio
async def test_tui3_word_by_word_seed_entry_feeds_create_profile_screen() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: []

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(CreateProfileScreen())
        await pilot.pause()
        create_screen = app.screen
        assert isinstance(create_screen, CreateProfileScreen)
        create_screen.query_one("#create-words").press()
        await pilot.pause()
        assert isinstance(app.screen, SeedWordsScreen)
        for idx, word in enumerate(
            [
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "abandon",
                "about",
            ],
            start=1,
        ):
            app.screen.query_one(f"#seed-word-{idx}", Input).value = word
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, SeedWordsReviewScreen)
        app.screen.query_one("#seed-review-confirm").press()
        await pilot.pause()
        assert isinstance(app.screen, CreateProfileScreen)
        assert app.screen.query_one("#create-mode", Input).value == "words"
        assert (
            app.screen.query_one("#create-seed", Input).value
            == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )


@pytest.mark.anyio
async def test_tui3_word_entry_flags_invalid_bip39_word() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: []

    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(SeedWordsScreen(on_done=lambda _phrase: None))
        await pilot.pause()
        app.screen.query_one("#seed-word-1", Input).value = "notaword"
        await pilot.pause()
        status = str(app.screen.query_one("#seed-words-status").render())
        progress = str(app.screen.query_one("#seed-words-progress").render())
        assert "not in the BIP-39 wordlist" in status
        assert "invalid: 1" in progress
