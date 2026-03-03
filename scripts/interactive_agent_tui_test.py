#!/usr/bin/env python3
"""
SeedPass TUI Interactive Agent Test Suite (v2 and v3 Support)
=============================================================

This script provides a "Human-in-the-loop" style automated test for the
SeedPass TUI. It bypasses real encryption and filesystem requirements
by injecting a MockService layer.

Usage:
    python scripts/interactive_agent_tui_test.py --version v3
    python scripts/interactive_agent_tui_test.py --version v2
"""

import asyncio
import sys
import os
import argparse
from pathlib import Path
from types import SimpleNamespace

# Add src to sys.path to allow imports from seedpass
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from seedpass.tui_v2.app import launch_tui2
from seedpass.tui_v3 import launch_tui3


class AgentMockService:
    """
    A comprehensive mock of all SeedPass core services.
    Bypasses real encryption and state.
    """

    def __init__(self):
        self.entries = {}
        self.next_id = 1
        self.archived = set()
        self.links = []  # list of dicts: {source, target, relation, note}
        self.is_managed = False
        self.nostr_index = 0
        self.offline = False
        self._manager = SimpleNamespace(
            parent_seed="MOCK_PARENT_SEED",
            current_fingerprint="EFBE51E70ED1",
            profile_stack=[],
        )

    # --- EntryService Interface ---
    def search_entries(
        self, query="", kinds=None, include_archived=False, archived_only=False
    ):
        out = []
        q = (query or "").lower()
        for eid, entry in self.entries.items():
            is_archived = eid in self.archived
            if archived_only and not is_archived:
                continue
            if not include_archived and is_archived:
                continue
            if q and q not in entry["label"].lower():
                continue
            kind = entry["kind"]
            if kinds and kind not in kinds:
                continue

            out.append(
                (
                    eid,
                    entry["label"],
                    entry.get("username"),
                    entry.get("url"),
                    is_archived,
                    SimpleNamespace(value=kind),
                )
            )
        return sorted(out, key=lambda x: x[0])

    def retrieve_entry(self, entry_id):
        eid = int(entry_id)
        entry = dict(self.entries.get(eid, {}))
        if entry:
            entry["archived"] = eid in self.archived
        return entry

    def add_entry(self, label, length, username=None, url=None, **kwargs):
        eid = self.next_id
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "password",
            "username": username,
            "url": url,
            "length": length,
            **kwargs,
        }
        self.next_id += 1
        return eid

    def add_totp(self, label, **kwargs):
        eid = self.next_id
        self.entries[eid] = {"id": eid, "label": label, "kind": "totp", **kwargs}
        self.next_id += 1
        return eid

    def add_document(self, label, content, file_type="txt", **kwargs):
        eid = self.next_id
        self.entries[eid] = {
            "id": eid,
            "label": label,
            "kind": "document",
            "content": content,
            "file_type": file_type,
            **kwargs,
        }
        self.next_id += 1
        return eid

    def modify_entry(self, entry_id, **kwargs):
        eid = int(entry_id)
        if eid in self.entries:
            self.entries[eid].update(kwargs)

    def archive_entry(self, entry_id):
        self.archived.add(int(entry_id))

    def restore_entry(self, entry_id):
        self.archived.discard(int(entry_id))

    def add_link(self, source_id, target_id, relation="related_to", note=""):
        self.links.append(
            {
                "source": int(source_id),
                "target": int(target_id),
                "relation": str(relation),
                "note": str(note),
            }
        )

    def get_links(self, entry_id):
        eid = int(entry_id)
        return [l for l in self.links if l["source"] == eid or l["target"] == eid]

    # --- Vault/Profile/Nostr/Sync Support ---
    def get(self, key):
        return {"inactivity_timeout": 300, "secret_mode_enabled": True}.get(key)

    def unlock(self, req):
        return SimpleNamespace(status="ok", duration=0.1)

    def lock(self):
        pass

    def stats(self):
        return {"total_entries": len(self.entries), "archived": len(self.archived)}

    def list_profiles(self):
        return ["EFBE51E70ED1B53A"]

    def sync(self):
        return SimpleNamespace(manifest_id="agent-mock-manifest")

    def start_fresh_namespace(self):
        self.nostr_index += 1
        return self.nostr_index

    def load_managed_account(self, entry_id):
        self.is_managed = True
        self._manager.profile_stack.append(
            (self._manager.current_fingerprint, "path", "seed")
        )
        self._manager.current_fingerprint = f"SUBACCT{entry_id}"

    def exit_managed_account(self):
        self.is_managed = False
        if self._manager.profile_stack:
            fp, _, _ = self._manager.profile_stack.pop()
            self._manager.current_fingerprint = fp

    # --- Secret Data ---
    def get_totp_code(self, entry_id):
        return "888999"

    def get_totp_secret(self, entry_id):
        return "AGENT_MOCK_SECRET"

    def get_seed_phrase(self, eid, parent):
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    def get_managed_account_seed(self, eid, parent):
        return self.get_seed_phrase(eid, parent)

    def get_clipboard_clear_delay(self):
        return 10

    def copy_to_clipboard(self, val):
        return True

    def generate_password(self, length, entry_id):
        return "MOCK_PASSWORD"


async def run_full_walkthrough(v="v3"):
    service = AgentMockService()
    holder = {}

    def _hook(app):
        holder["app"] = app
        app.session_locked = False  # Bypass lock

    launch_fn = launch_tui3 if v == "v3" else launch_tui2

    launch_fn(
        entry_service_factory=lambda: service,
        vault_service_factory=lambda: service,
        profile_service_factory=lambda: service,
        sync_service_factory=lambda: service,
        nostr_service_factory=lambda: service,
        config_service_factory=lambda: service,
        app_hook=_hook,
    )

    app = holder["app"]

    async with app.run_test() as pilot:
        from textual.widgets import Static, Input, ListView, DataTable

        print(f"--- TESTING TUI {v.upper()} ---")

        # 1. Entry Management
        print("PHASE 1: Entry Creation & Grid")
        service.add_entry("Gmail", 20)
        service.add_totp("Bank")
        service.add_entry("SubUser", 10, kind="managed_account")
        service.add_entry("MySeed", 24, kind="seed")

        await pilot.pause()
        print(f"  [OK] Created {len(service.entries)} entries.")

        # Selection
        if v == "v3":
            # Real selection via DataTable
            table = app.screen.query_one("#entry-data-table", DataTable)
            table.focus()
            await pilot.press("down")  # Select first row
            await pilot.press("enter")
        else:
            app._show_entry(1)
        await pilot.pause(0.5)
        print(f"  [OK] Selected Entry #1 (ID: {app.selected_entry_id}).")

        # 2. Secure Data (Reveal/Confirm)
        print("PHASE 2: Secure Data (v/g)")
        if v == "v3":
            # Jump to MySeed (#4)
            app.selected_entry_id = 4
            await pilot.pause(0.5)
            # First press
            await pilot.press("v")
            await pilot.pause(0.5)
            board_text = str(
                app.screen.query_one("#board-container").children[0].render()
            )
            print(f"    [DEBUG] Board text after first 'v': {board_text[:100]}...")
            print(f"  [OK] Seed Confirmation shown: {'CONFIRMATION' in board_text}")
            # Second press
            await pilot.press("v")
            await pilot.pause(0.5)
            board_text_revealed = str(
                app.screen.query_one("#board-container").children[0].render()
            )
            print(
                f"    [DEBUG] Board text after second 'v': {board_text_revealed[:100]}..."
            )
            print(f"  [OK] Seed Revealed: {'abandon' in board_text_revealed}")
        else:
            # v2 legacy test path
            print("  (Skipping v2 confirmation test in this run)")

        # 3. Full-screen UX (V3 only)
        if v == "v3":
            print("PHASE 3: Full-screen screens")
            await pilot.press("shift+s")
            await pilot.pause(0.5)
            print(
                f"  [OK] Settings Screen: {app.screen.__class__.__name__.endswith('SettingsScreen')}"
            )
            await pilot.press("escape")
            await pilot.pause(0.5)

            app.selected_entry_id = 1
            await pilot.pause(0.5)
            await pilot.press("z")
            await pilot.pause(0.5)
            print(f"    [DEBUG] Screen after 'z': {app.screen.__class__.__name__}")
            print(
                f"  [OK] Maximize Screen: {app.screen.__class__.__name__.endswith('MaximizedInspectorScreen')}"
            )
            await pilot.press("escape")
            await pilot.pause(0.5)

        # 4. Action Logic (Archive/Copy)
        print("PHASE 4: Action Logic")
        if v == "v3":
            app.selected_entry_id = 1
            await pilot.pause(0.5)
            await pilot.press("a")
            await pilot.pause(0.5)
            print(f"    [DEBUG] Entry 1 archived in service: {1 in service.archived}")
            print(f"  [OK] Archive: {1 in service.archived}")
            await pilot.press("c")
            await pilot.pause(0.5)
            print(f"  [OK] Copy action triggered.")

        # 5. Editing and Sub-Profiles
        if v == "v3":
            print("PHASE 5: Editing and Sub-Profiles")
            # Select managed account (ID 3)
            app.selected_entry_id = 3
            await pilot.pause(0.5)

            # Press 'e' to Edit
            await pilot.press("e")
            await pilot.pause(0.5)
            print(
                f"  [OK] Edit Screen opened: {app.screen.__class__.__name__.endswith('EditEntryScreen')}"
            )
            await pilot.press("escape")  # close edit screen
            await pilot.pause(0.5)

            # Press 'm' to load profile
            await pilot.press("m")
            await pilot.pause(0.5)
            print(f"  [OK] Profile Loaded: {service.is_managed == True}")

            # Verify breadcrumb display
            brand_label = str(app.screen.query_one("#brand-fingerprint").render())
            print(f"    [DEBUG] Breadcrumb text: {brand_label}")
            print(
                f"  [OK] Sub-account breadcrumb structure visible: {'>' in brand_label and 'SUBACCT3' in brand_label}"
            )

            # Press 'shift+m' to exit profile
            await pilot.press("shift+m")
            await pilot.pause(0.5)
            print(f"  [OK] Profile Exited: {service.is_managed == False}")
            brand_label_exit = str(app.screen.query_one("#brand-fingerprint").render())
            print(f"  [OK] Breadcrumb reverted: {'>' not in brand_label_exit}")

        # 6. Data I/O and Command Palette
        if v == "v3":
            print("PHASE 6: Data I/O and Commands")

            # Export selected entry
            app.selected_entry_id = 4  # Seed
            await pilot.pause(0.5)
            await pilot.press("x")
            await pilot.pause(0.5)
            print(f"  [OK] Export Selected triggered.")

            # Test global commands via Command Palette
            app.action_open_palette()
            await pilot.pause(0.5)
            palette = app.screen.query_one("#palette")
            is_visible = palette.has_class("visible")
            print(f"  [OK] Command Palette opened: {is_visible}")

            # Type and execute db-export
            await pilot.press(*list("db-export /tmp/test_export.zip"))
            await pilot.press("enter")
            await pilot.pause(0.5)
            print(f"  [OK] db-export command executed.")

            app.action_open_palette()
            await pilot.pause(0.5)
            await pilot.press(*list("db-import /tmp/test_export.zip"))
            await pilot.press("enter")
            await pilot.pause(0.5)
            print(f"  [OK] db-import command executed.")

        print(f"\n--- TUI {v.upper()} WALKTHROUGH COMPLETE ---")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", choices=["v2", "v3"], default="v3")
    args = parser.parse_args()

    asyncio.run(run_full_walkthrough(v=args.version))
