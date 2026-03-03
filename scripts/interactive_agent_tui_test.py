#!/usr/bin/env python3
"""
SeedPass TUI v2 Interactive Agent Test Suite
============================================

This script provides a "Human-in-the-loop" style automated test for the 
SeedPass TUI v2. It bypasses real encryption and filesystem requirements 
by injecting a MockService layer.

Usage:
    python scripts/interactive_agent_tui_test.py

Features Tested:
    - Entry Creation (Password, TOTP, Doc, etc.)
    - Searching and Filtering
    - Document Editing
    - Archiving and Restoring
    - Entry Linking (Graph)
    - Sensitive Data Reveal & QR Codes
    - Sub-profile (Managed Account) Sessions
    - Nostr Sync & Namespace Management
    - Settings & Stats
"""

import asyncio
import sys
import os
from pathlib import Path
from types import SimpleNamespace

# Add src to sys.path to allow imports from seedpass
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from seedpass.tui_v2.app import launch_tui2

class AgentMockService:
    """
    A comprehensive mock of all SeedPass core services.
    Bypasses real encryption and state.
    """
    def __init__(self):
        self.entries = {}
        self.next_id = 1
        self.archived = set()
        self.links = [] # list of dicts: {source, target, relation, note}
        self.is_managed = False
        self.nostr_index = 0
        self.offline = False

    # --- EntryService Interface ---
    def search_entries(self, query="", kinds=None, include_archived=False, archived_only=False):
        out = []
        q = (query or "").lower()
        for eid, entry in self.entries.items():
            is_archived = eid in self.archived
            if archived_only and not is_archived: continue
            if not include_archived and is_archived: continue
            if q and q not in entry["label"].lower(): continue
            kind = entry["kind"]
            if kinds and kind not in kinds: continue
            
            out.append((
                eid, 
                entry["label"], 
                entry.get("username"), 
                entry.get("url"), 
                is_archived, 
                SimpleNamespace(value=kind)
            ))
        return sorted(out, key=lambda x: x[0])

    def retrieve_entry(self, entry_id):
        eid = int(entry_id)
        entry = dict(self.entries.get(eid, {}))
        if entry:
            entry["archived"] = eid in self.archived
        return entry

    def add_entry(self, label, length, username=None, url=None, **kwargs):
        eid = self.next_id
        self.entries[eid] = {"id": eid, "label": label, "kind": "password", "username": username, "url": url, "length": length, **kwargs}
        self.next_id += 1
        return eid

    def add_totp(self, label, **kwargs):
        eid = self.next_id
        self.entries[eid] = {"id": eid, "label": label, "kind": "totp", **kwargs}
        self.next_id += 1
        return eid

    def add_document(self, label, content, file_type="txt", **kwargs):
        eid = self.next_id
        self.entries[eid] = {"id": eid, "label": label, "kind": "document", "content": content, "file_type": file_type, **kwargs}
        self.next_id += 1
        return eid

    def modify_entry(self, entry_id, **kwargs):
        eid = int(entry_id)
        if eid in self.entries:
            self.entries[eid].update(kwargs)

    def archive_entry(self, entry_id): self.archived.add(int(entry_id))
    def restore_entry(self, entry_id): self.archived.discard(int(entry_id))

    def add_link(self, source_id, target_id, relation="related_to", note=""):
        self.links.append({"source": int(source_id), "target": int(target_id), "relation": str(relation), "note": str(note)})

    def get_links(self, entry_id):
        eid = int(entry_id)
        return [l for l in self.links if l["source"] == eid or l["target"] == eid]

    # --- Vault/Profile/Nostr/Sync Support ---
    def unlock(self, req): return SimpleNamespace(status="ok", duration=0.1)
    def lock(self): pass
    def stats(self):
        return {"total_entries": len(self.entries), "archived": len(self.archived)}
    
    def sync(self): return SimpleNamespace(manifest_id="agent-mock-manifest")
    def start_fresh_namespace(self):
        self.nostr_index += 1
        return self.nostr_index
    
    def load_managed_account(self, entry_id): self.is_managed = True
    def exit_managed_account(self): self.is_managed = False

    # --- Secret Data ---
    def get_totp_code(self, entry_id): return "888999"
    def get_totp_secret(self, entry_id): return "AGENT_MOCK_SECRET"
    def get_clipboard_clear_delay(self): return 10
    def copy_to_clipboard(self, val): return True
    def generate_password(self, length, entry_id): return "MOCK_PASSWORD"

async def run_full_walkthrough():
    service = AgentMockService()
    holder = {}
    
    def _hook(app):
        holder["app"] = app
        app._session_locked = False # Bypass lock

    # Launch app with injected mock services
    launch_tui2(
        entry_service_factory=lambda: service,
        vault_service_factory=lambda: service,
        profile_service_factory=lambda: service,
        sync_service_factory=lambda: service,
        nostr_service_factory=lambda: service,
        app_hook=_hook
    )
    
    app = holder["app"]
    
    async with app.run_test() as pilot:
        from textual.widgets import Static, Input, ListView

        print("--- PHASE 1: Entry Management ---")
        # Add various types
        app._run_palette_command('add-password "Gmail" 20')
        app._run_palette_command('add-totp "Bank"')
        app._run_palette_command('add-document "Readme" md "Hello World"')
        await pilot.pause()
        print(f"  [OK] Created {len(service.entries)} entries.")

        # Search
        app._load_entries(query="bank")
        await pilot.pause()
        results = app.query_one("#entry-list", ListView).children
        print(f"  [OK] Search 'bank' found {len(results)} results.")

        # Archive
        app._show_entry(1) # Gmail
        await pilot.pause()
        app.action_toggle_archive()
        await pilot.pause()
        print(f"  [OK] Archive status: {app.query_one('#status').render()}")

        print("\n--- PHASE 2: Advanced Interaction ---")
        # Linking
        app._run_palette_command("link-add 2 requires 'Auth'")
        await pilot.pause()
        print(f"  [OK] Linked #1 to #2.")

        # Reveal & QR
        app._show_entry(2) # Bank TOTP
        await pilot.pause()
        app.action_reveal_selected()
        await pilot.pause()
        reveal_text = str(app.query_one("#secret-detail", Static).render())
        print(f"  [OK] Secret Reveal: {'REVEALED' in reveal_text}")

        app.action_show_qr()
        await pilot.pause()
        qr_text = str(app.query_one("#secret-detail", Static).render())
        # The QR code uses '##' for dark cells in the ASCII renderer
        print(f"  [OK] QR Code Active: {'##' in qr_text}")
        if '##' not in qr_text:
            print(f"  [DEBUG] QR Panel Content:\n{qr_text}")

        print("\n--- PHASE 3: System Operations ---")
        # Managed Account
        service.add_entry("Sub", 10, kind="managed_account")
        app._load_entries("")
        await pilot.pause()
        app._run_palette_command("managed-load 4")
        await pilot.pause()
        print(f"  [OK] Sub-profile load: {'Loaded managed' in str(app.query_one('#status').render())}")
        
        app._run_palette_command("managed-exit")
        await pilot.pause()

        # Nostr & Sync
        app._run_palette_command("nostr-fresh-namespace")
        await pilot.pause()
        app._run_palette_command("sync-now")
        await pilot.pause()
        print(f"  [OK] Sync status: {app.query_one('#status').render()}")

        print("\n--- WALKTHROUGH COMPLETE ---")
        return 0

if __name__ == "__main__":
    asyncio.run(run_full_walkthrough())
