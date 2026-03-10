from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Button, DataTable, Input, Static

from seedpass.tui_v3 import launch_tui3
from seedpass.tui_v3.app import (
    BackupParentSeedScreen,
    CreateProfileScreen,
    RecoverProfileScreen,
    SeedPassTuiV3,
    SeedWordsScreen,
    SeedWordsReviewScreen,
    StartupScreen,
)
from seedpass.tui_v3.screens.profile import ProfileManagementScreen
from seedpass.tui_v3.screens.atlas import AtlasWayfinderScreen
from seedpass.tui_v3.screens.pubkey import NostrPubkeyScreen
from seedpass.tui_v3.screens.relays import RelaysScreen
from seedpass.tui_v3.screens.security import ChangePasswordScreen
from seedpass.tui_v3.screens.settings import SettingsScreen
from seedpass.tui_v3.widgets.inspector import UtilityHintsBar


class V3EntryService:
    def __init__(self) -> None:
        self._entries: dict[int, dict] = {
            1: {
                "id": 1,
                "kind": "password",
                "label": "Email",
                "length": 16,
                "links": [{"target_id": 2, "relation": "references"}],
            },
            2: {
                "id": 2,
                "kind": "managed_account",
                "label": "Managed Ops",
            },
            3: {
                "id": 3,
                "kind": "nostr",
                "label": "Agent Nostr",
                "links": [{"target_id": 1, "relation": "uses"}],
            },
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

    def delete_entry(self, entry_id: int) -> None:
        self._entries.pop(int(entry_id), None)

    def copy_to_clipboard(self, value: str) -> bool:
        self.copied.append(value)
        return True


class V3ProfileService:
    def __init__(self) -> None:
        self.profiles = ["EFBE51E70ED1B53A", "AABBCCDDEEFF0011"]
        self.switch_calls: list[tuple[str, str | None]] = []
        self.remove_calls: list[str] = []

    def list_profiles(self) -> list[str]:
        return list(self.profiles)

    def switch_profile(self, req) -> None:
        self.switch_calls.append((req.fingerprint, req.password))

    def remove_profile(self, req) -> None:
        self.remove_calls.append(req.fingerprint)
        self.profiles = [fp for fp in self.profiles if fp != req.fingerprint]


class V3VaultService:
    def __init__(self) -> None:
        self.locked = False
        self.last_unlock_password: str | None = None
        self._manager = SimpleNamespace(parent_seed="PARENT_SEED")
        self.changed_passwords: list[tuple[str, str]] = []
        self.backup_requests: list[tuple[str | None, str | None]] = []

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

    def change_password(self, request) -> None:
        self.changed_passwords.append((request.old_password, request.new_password))

    def backup_parent_seed(self, request) -> None:
        path = None if request.path is None else str(request.path)
        self.backup_requests.append((path, request.password))


class V3NostrService:
    def __init__(self) -> None:
        self.reset_calls = 0
        self.fresh_calls = 0
        self.relays = ["wss://relay.one", "wss://relay.two"]
        self.removed_relays: list[int] = []

    def get_pubkey(self) -> str:
        return "npub1seedpassprofile"

    def list_relays(self) -> list[str]:
        return list(self.relays)

    def add_relay(self, url: str) -> None:
        self.relays.append(url)

    def remove_relay(self, idx: int) -> None:
        self.removed_relays.append(idx)
        self.relays.pop(idx)

    def reset_sync_state(self) -> int:
        self.reset_calls += 1
        return 0

    def start_fresh_namespace(self) -> int:
        self.fresh_calls += 1
        return 1


class V3AtlasService:
    def wayfinder(self) -> dict:
        return {
            "scope_path": "seed/EFBE51E70ED1B53A",
            "stats": {"event_count": 4, "checkpoint_count": 1, "writer_count": 1},
            "counts_by_kind": {
                "data": {"counts": {"password": 1, "nostr": 1, "managed_account": 1}}
            },
            "children_of": {
                "data": {
                    "children": [
                        {"entry_id": "1", "label": "Email", "kind": "password"},
                        {
                            "entry_id": "2",
                            "label": "Managed Ops",
                            "kind": "managed_account",
                        },
                    ]
                }
            },
            "recent_activity": {
                "data": {
                    "items": [
                        {
                            "event_type": "entry_created",
                            "subject_id": "1",
                            "subject_kind": "password",
                            "summary": "Created password entry",
                        }
                    ]
                }
            },
        }


class V3SearchService:
    def __init__(self, entry: V3EntryService) -> None:
        self.entry = entry
        self.calls: list[dict] = []
        self.link_calls: list[dict] = []

    def search(
        self,
        query: str,
        *,
        kinds: list[str] | None = None,
        include_archived: bool = False,
        archived_only: bool = False,
        mode: str | None = None,
        sort: str = "relevance",
        limit: int = 200,
        tags: list[str] | None = None,
        linked_to: int | None = None,
    ) -> list[dict]:
        self.calls.append(
            {
                "query": query,
                "kinds": kinds,
                "include_archived": include_archived,
                "archived_only": archived_only,
                "mode": mode,
                "sort": sort,
                "limit": limit,
                "tags": tags,
                "linked_to": linked_to,
            }
        )
        rows = self.entry.search_entries(
            query,
            kinds=kinds,
            include_archived=include_archived,
            archived_only=archived_only,
        )
        out: list[dict] = []
        for row in rows:
            entry_id, label, user, url, archived, kind = row
            out.append(
                {
                    "entry_id": entry_id,
                    "label": label,
                    "kind": kind.value,
                    "scope_path": "seed/EFBE51E70ED1B53A",
                    "archived": archived,
                    "score": 1.0,
                    "score_breakdown": {
                        "lexical": 1.0,
                        "semantic": 0.0,
                        "structural": 0.0,
                        "recency": 0.0,
                    },
                    "match_reasons": ["label_match"] if query else [],
                    "excerpt": "",
                    "linked_hits": [],
                    "tags": [],
                    "modified_ts": 0,
                    "meta": user or url or "",
                }
            )
        return out

    def linked_neighbors(
        self,
        entry_id: int,
        *,
        relation: str | None = None,
        direction: str = "both",
        include_archived: bool = True,
        limit: int = 50,
    ) -> list[dict]:
        _ = (include_archived, limit)
        self.link_calls.append(
            {
                "entry_id": entry_id,
                "relation": relation,
                "direction": direction,
            }
        )
        if int(entry_id) == 1:
            rows = [
                {
                    "entry_id": 2,
                    "label": "Managed Ops",
                    "kind": "managed_account",
                    "archived": False,
                    "direction": "outgoing",
                    "relation": "references",
                },
                {
                    "entry_id": 3,
                    "label": "Agent Nostr",
                    "kind": "nostr",
                    "archived": False,
                    "direction": "incoming",
                    "relation": "uses",
                },
            ]
            if relation:
                return [row for row in rows if row["relation"] == relation]
            return rows
        return []

    def relation_summary(
        self,
        entry_id: int,
        *,
        include_archived: bool = True,
    ) -> dict[str, dict[str, int]]:
        _ = include_archived
        if int(entry_id) != 1:
            return {"incoming": {}, "outgoing": {}, "combined": {}}
        return {
            "incoming": {"uses": 1},
            "outgoing": {"references": 1},
            "combined": {"references": 1, "uses": 1},
        }


def _build_app() -> tuple[object, V3EntryService, V3VaultService, V3SearchService]:
    holder: dict[str, object] = {}
    entry = V3EntryService()
    vault = V3VaultService()
    profile = V3ProfileService()
    nostr = V3NostrService()
    atlas = V3AtlasService()
    search = V3SearchService(entry)

    def _hook(app):
        holder["app"] = app

    launched = launch_tui3(
        fingerprint="EFBE51E70ED1B53A",
        entry_service_factory=lambda: entry,
        profile_service_factory=lambda: profile,
        vault_service_factory=lambda: vault,
        nostr_service_factory=lambda: nostr,
        atlas_service_factory=lambda: atlas,
        search_service_factory=lambda: search,
        app_hook=_hook,
    )
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app, entry, vault, search


@pytest.mark.anyio
async def test_tui3_palette_lock_unlock_and_session_status() -> None:
    app, _entry, vault, _search = _build_app()
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
    app, _entry, _vault, _search = _build_app()
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
    app, entry, _vault, _search = _build_app()
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
async def test_tui3_grid_uses_search_service_for_query_and_mode() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#entry-data-table", DataTable)
        app.search_mode = "hybrid"
        table._refresh_data("Email")
        await pilot.pause()
        assert search.calls
        assert search.calls[-1]["query"] == "Email"
        assert search.calls[-1]["mode"] == "hybrid"
        assert table.row_count >= 1


@pytest.mark.anyio
async def test_tui3_main_grid_has_default_focus_and_keyboard_navigation() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#entry-data-table", DataTable)
        assert app.focused is table
        assert app.selected_entry_id is None

        await pilot.press("down")
        await pilot.pause()

        assert app.focused is table
        assert app.selected_entry_id == 2
        assert table.cursor_coordinate.row == 1


@pytest.mark.anyio
async def test_tui3_palette_close_restores_focus_to_main_grid() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#entry-data-table", DataTable)
        palette_input = app.screen.query_one("#palette-input", Input)

        app.action_open_palette()
        await pilot.pause()
        assert app.focused is palette_input

        app.action_open_palette()
        await pilot.pause()
        assert app.focused is table

        await pilot.press("down")
        await pilot.pause()
        assert app.selected_entry_id == 2


@pytest.mark.anyio
async def test_tui3_grid_toolbar_updates_filter_mode_and_sort() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#grid-filter-keys", Button).press()
        await pilot.pause()
        assert app.filter_kind == "keys"

        app.screen.query_one("#grid-mode-hybrid", Button).press()
        await pilot.pause()
        assert app.search_mode == "hybrid"

        app.screen.query_one("#grid-sort-most_linked", Button).press()
        await pilot.pause()
        assert app.search_sort == "most_linked"
        assert search.calls
        assert search.calls[-1]["sort"] == "most_linked"


@pytest.mark.anyio
async def test_tui3_search_query_persists_across_refresh() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_search("Email")
        await pilot.pause()
        assert app.search_query == "Email"
        assert search.calls[-1]["query"] == "Email"

        app.action_set_kind_filter("all")
        await pilot.pause()
        assert search.calls[-1]["query"] == "Email"


@pytest.mark.anyio
async def test_tui3_linked_items_panel_shows_neighbors_and_opens_entry() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.selected_entry_id = 1
        await pilot.pause()

        summary = app.screen.query_one("#linked-items-summary", Static)
        assert "Outgoing references:1" in str(summary.render())
        assert "Incoming uses:1" in str(summary.render())
        assert search.link_calls[-1]["entry_id"] == 1

        open_button = app.screen.query_one("#linked-open-2", Button)
        open_button.press()
        await pilot.pause()
        assert app.selected_entry_id == 2


@pytest.mark.anyio
async def test_tui3_inspector_stays_collapsed_until_selection_and_can_close() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        inspector = app.screen.query_one("#inspector-pane")
        close_button = app.screen.query_one("#inspector-close", Button)
        assert close_button.label.plain == "Close"
        assert inspector.has_class("hidden")

        app.selected_entry_id = 1
        await pilot.pause()
        assert not inspector.has_class("hidden")

        app.action_close_inspector()
        await pilot.pause()
        assert app.selected_entry_id is None
        assert inspector.has_class("hidden")


@pytest.mark.anyio
async def test_tui3_palette_can_open_atlas_wayfinder() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.processor.execute("atlas")
        await pilot.pause()
        assert isinstance(app.screen, AtlasWayfinderScreen)
        content = str(app.screen.query_one("#atlas-wayfinder-content", Static).render())
        assert "Counts By Kind" in str(content)
        assert "Managed Ops" in str(content)


@pytest.mark.anyio
async def test_tui3_wayfinder_screen_can_open_entry_and_apply_filter() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_open_atlas_wayfinder()
        await pilot.pause()
        assert isinstance(app.screen, AtlasWayfinderScreen)

        app.screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="atlas-open-entry-1"))
        )
        await pilot.pause()
        assert app.selected_entry_id == 1
        assert not isinstance(app.screen, AtlasWayfinderScreen)

        app.action_open_atlas_wayfinder()
        await pilot.pause()
        app.screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="atlas-filter-docs"))
        )
        await pilot.pause()
        assert app.filter_kind == "docs"
        assert not isinstance(app.screen, AtlasWayfinderScreen)


@pytest.mark.anyio
async def test_tui3_main_workspace_shows_atlas_strip() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        content = str(app.screen.query_one("#atlas-strip", Static).render())
        assert "Wayfinder" in content
        assert "password:1" in content
        assert "entry_created #1" in content
        assert "open_atlas_wayfinder" in str(
            app.screen.query_one("#action-bar", Static).render()
        )


@pytest.mark.anyio
async def test_tui3_delete_selected_requires_confirm_and_clears_selection() -> None:
    app, entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.selected_entry_id = 1
        await pilot.pause()

        app.action_delete_selected()
        await pilot.pause()
        assert 1 in entry._entries
        assert app.selected_entry_id == 1

        app.action_delete_selected()
        await pilot.pause()
        assert 1 not in entry._entries
        assert app.selected_entry_id is None


@pytest.mark.anyio
async def test_tui3_nostr_maintenance_commands_open_pubkey_and_call_services() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        nostr = app.services["nostr"]

        app.processor.execute("npub")
        await pilot.pause()
        assert isinstance(app.screen, NostrPubkeyScreen)
        content = app.screen.query_one("#pubkey-content", Static).render()
        assert "npub1seedpassprofile" in str(content)

        app.pop_screen()
        await pilot.pause()
        app.processor.execute("nostr-reset-sync-state")
        app.processor.execute("nostr-fresh-namespace")
        await pilot.pause()
        assert nostr.reset_calls == 1
        assert nostr.fresh_calls == 1


@pytest.mark.anyio
async def test_tui3_change_password_and_seed_backup_flows_use_vault_service() -> None:
    app, _entry, vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        app.processor.execute("change-password")
        await pilot.pause()
        assert isinstance(app.screen, ChangePasswordScreen)
        assert (
            "current password to authorize"
            in str(
                app.screen.query_one("#change-password-intro", Static).render()
            ).lower()
        )
        app.screen.query_one("#change-password-old", Input).value = "old-pass"
        app.screen.query_one("#change-password-new", Input).value = "new-pass"
        app.screen.query_one("#change-password-confirm", Input).value = "new-pass"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert vault.changed_passwords == [("old-pass", "new-pass")]

        app.processor.execute("backup-parent-seed /tmp/seed-backup.enc pw123")
        await pilot.pause()
        assert vault.backup_requests[-1] == ("/tmp/seed-backup.enc", "pw123")

        app.processor.execute("backup-parent-seed")
        await pilot.pause()
        assert isinstance(app.screen, BackupParentSeedScreen)
        app.screen.query_one("#backup-seed-path", Input).value = "/tmp/seed-second.enc"
        app.screen.query_one("#backup-seed-password", Input).value = "pw456"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert vault.backup_requests[-1] == ("/tmp/seed-second.enc", "pw456")


@pytest.mark.anyio
async def test_tui3_profile_management_switch_and_remove_flow_use_profile_service() -> (
    None
):
    app, _entry, _vault, _search = _build_app()
    app._list_boot_profiles = lambda: [
        {"fingerprint": "EFBE51E70ED1B53A", "label": "Primary Ops Seed"},
        {"fingerprint": "AABBCCDDEEFF0011", "label": "Recovery Seed"},
    ]
    async with app.run_test() as pilot:
        await pilot.pause()
        profile = app.services["profile"]

        app.processor.execute("profiles")
        await pilot.pause()
        assert isinstance(app.screen, ProfileManagementScreen)
        intro = str(app.screen.query_one("#profile-intro", Static).render()).lower()
        assert "removing a profile is permanent and requires confirmation" in intro
        listing = str(app.screen.query_one("#profile-list", Static).render())
        assert "Primary Ops Seed" in listing
        assert "Recovery Seed" in listing
        app.screen.query_one("#profile-choice", Input).value = "2"
        app.screen.query_one("#profile-password", Input).value = "hunter2"
        app.screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="profile-switch"))
        )
        await pilot.pause()
        assert profile.switch_calls == [("AABBCCDDEEFF0011", "hunter2")]
        assert app.active_fingerprint == "AABBCCDDEEFF0011"

        app.screen.query_one("#profile-choice", Input).value = "1"
        app.screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="profile-remove"))
        )
        await pilot.pause()
        assert profile.remove_calls == []
        status = str(app.screen.query_one("#profile-status", Static).render())
        assert "press Remove again" in status
        app.screen.on_button_pressed(
            SimpleNamespace(button=SimpleNamespace(id="profile-remove"))
        )
        await pilot.pause()
        assert profile.remove_calls == ["EFBE51E70ED1B53A"]


@pytest.mark.anyio
async def test_tui3_relay_delete_requires_second_confirm() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        nostr = app.services["nostr"]

        app.processor.execute("relay-list")
        await pilot.pause()
        assert isinstance(app.screen, RelaysScreen)
        app.screen.action_delete_relay()
        await pilot.pause()
        assert nostr.removed_relays == []
        status = str(app.screen.query_one("#relays-status", Static).render())
        assert "Press Delete again" in status

        app.screen.action_delete_relay()
        await pilot.pause()
        assert nostr.removed_relays == [0]


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
        assert "Import an existing seed" in str(
            screen.query_one("#create-status", Static).render()
        )
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
async def test_tui3_recover_profile_sets_success_status_before_bootstrap() -> None:
    app = SeedPassTuiV3()
    app._list_boot_profiles = lambda: [
        {"fingerprint": "EFBE51E70ED1B53A", "label": "Primary (EFBE51E70ED1B53A)"}
    ]
    booted: dict[str, str] = {}
    status_at_boot: list[str] = []

    def _recover_profile(*, fingerprint: str, seed: str, password: str) -> None:
        pass

    def _bootstrap(fingerprint: str, password: str) -> None:
        booted["fingerprint"] = fingerprint
        # Capture status text at the moment bootstrap fires
        try:
            status_at_boot.append(
                str(app.screen.query_one("#recover-status").render())
            )
        except Exception:
            pass

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
        assert booted.get("fingerprint") == "EFBE51E70ED1B53A"
        assert status_at_boot and "Recovery successful" in status_at_boot[0]


@pytest.mark.anyio
async def test_tui3_add_entry_screen_seedplus_hint_mentions_bip85() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_add_entry()
        await pilot.pause()
        screen = app.screen
        hint = str(screen.query_one("#seedplus-hint").render())
        assert "BIP-85" in hint
        assert "Seed+" in hint


@pytest.mark.anyio
async def test_tui3_seed_plus_screen_shows_deterministic_warning() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_seed_plus()
        await pilot.pause()
        screen = app.screen
        warning = str(screen.query_one("#seedplus-warning").render())
        assert "deterministic" in warning.lower()
        assert "index" in warning.lower()


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


@pytest.mark.anyio
async def test_tui3_settings_screen_shows_utility_maintenance_section() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_toggle_settings()
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        content = str(app.screen.query_one("#settings-content", Static).render())
        assert "UTILITY & MAINTENANCE" in content
        assert "db-export" in content
        assert "db-import" in content
        assert "checksum-verify" in content
        assert "stats" in content


@pytest.mark.anyio
async def test_tui3_inspector_utility_hints_update_by_entry_kind() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Select password entry (id=1)
        app.selected_entry_id = 1
        await pilot.pause()
        hints_bar = app.screen.query_one("#utility-hints-bar", UtilityHintsBar)
        hints_text = str(hints_bar.render())
        assert "reveal" in hints_text.lower()
        assert "copy" in hints_text.lower()

        # Select nostr entry (id=3) — should show npub hint
        app.selected_entry_id = 3
        await pilot.pause()
        hints_text = str(hints_bar.render())
        assert "npub" in hints_text.lower()

        # Deselect — hints bar should be empty
        app.selected_entry_id = None
        await pilot.pause()
        hints_text = str(hints_bar.render())
        assert "Actions" not in hints_text


@pytest.mark.anyio
async def test_tui3_keyboard_sort_shortcuts_change_sort() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        # Default sort is relevance
        assert app.search_sort == "relevance"

        # n → sort by label_asc
        await pilot.press("n")
        await pilot.pause()
        assert app.search_sort == "label_asc"
        assert search.calls and search.calls[-1]["sort"] == "label_asc"

        # r → sort by modified_desc
        await pilot.press("r")
        await pilot.pause()
        assert app.search_sort == "modified_desc"
        assert search.calls[-1]["sort"] == "modified_desc"

        # k → sort by kind
        await pilot.press("k")
        await pilot.pause()
        assert app.search_sort == "kind"
        assert search.calls[-1]["sort"] == "kind"


@pytest.mark.anyio
async def test_tui3_clear_filter_button_resets_state() -> None:
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Set non-default filter/sort/query state
        app.action_set_kind_filter("docs")
        app.action_set_search_sort("modified_desc")
        app.action_search("Email")
        await pilot.pause()
        assert app.filter_kind == "docs"
        assert app.search_sort == "modified_desc"
        assert app.search_query == "Email"

        # Press Clear button
        app.screen.query_one("#grid-clear-filter", Button).press()
        await pilot.pause()
        assert app.filter_kind == "all"
        assert app.search_sort == "relevance"
        assert app.search_query == ""


@pytest.mark.anyio
async def test_tui3_clear_filter_keyboard_shortcut_resets_state() -> None:
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_set_kind_filter("keys")
        app.action_set_search_sort("label_asc")
        await pilot.pause()
        assert app.filter_kind == "keys"

        await pilot.press("f")
        await pilot.pause()
        assert app.filter_kind == "all"
        assert app.search_sort == "relevance"


@pytest.mark.anyio
async def test_tui3_filter_sort_state_persists_across_screen_transitions() -> None:
    """Filter and sort state must survive pushing/popping overlay screens."""
    app, _entry, _vault, search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Establish non-default state
        app.action_set_kind_filter("secrets")
        app.action_set_search_sort("modified_desc")
        await pilot.pause()
        assert app.filter_kind == "secrets"
        assert app.search_sort == "modified_desc"

        # Push a screen (atlas wayfinder)
        app.action_open_atlas_wayfinder()
        await pilot.pause()
        assert isinstance(app.screen, AtlasWayfinderScreen)

        # Pop back to main
        app.pop_screen()
        await pilot.pause()
        # State must be unchanged
        assert app.filter_kind == "secrets"
        assert app.search_sort == "modified_desc"

        # Grid refresh triggered after pop should use persisted sort
        table = app.screen.query_one("#entry-data-table", DataTable)
        table._refresh_data()
        await pilot.pause()
        assert search.calls and search.calls[-1]["sort"] == "modified_desc"


@pytest.mark.anyio
async def test_tui3_toolbar_active_class_reflects_app_state() -> None:
    """GridToolbar buttons must gain/lose the 'active' CSS class as state changes."""
    app, _entry, _vault, _search = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Default: filter=all, mode=keyword, sort=relevance
        assert app.screen.query_one("#grid-filter-all", Button).has_class("active")
        assert app.screen.query_one("#grid-mode-keyword", Button).has_class("active")
        assert app.screen.query_one("#grid-sort-relevance", Button).has_class("active")
        assert not app.screen.query_one("#grid-filter-docs", Button).has_class("active")

        # Change filter to docs
        app.action_set_kind_filter("docs")
        await pilot.pause()
        assert app.screen.query_one("#grid-filter-docs", Button).has_class("active")
        assert not app.screen.query_one("#grid-filter-all", Button).has_class("active")

        # Change sort to label_asc
        app.action_set_search_sort("label_asc")
        await pilot.pause()
        assert app.screen.query_one("#grid-sort-label_asc", Button).has_class("active")
        assert not app.screen.query_one("#grid-sort-relevance", Button).has_class("active")
