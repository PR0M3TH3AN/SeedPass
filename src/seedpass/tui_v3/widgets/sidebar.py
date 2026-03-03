from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Tree, Static
from textual.widgets.tree import TreeNode

class ProfileTree(Tree):
    """
    A hierarchical sidebar that manages Seed Profiles, Managed Accounts, and Agents.
    
    Structure:
    Root (Hidden)
    ├── Fingerprint (Parent Seed)
    │   ├── Managed Account 1
    │   │   └── Agent 1
    │   └── Managed Account 2
    └── External Fingerprint
    """
    
    def on_mount(self) -> None:
        self.root.expand()
        self._refresh_tree()

    def _refresh_tree(self) -> None:
        self.clear()
        app = self.app
        if "profile" not in app.services:
            self.root.add_leaf("Profile Service Offline")
            return

        service = app.services["profile"]
        entry_service = app.services.get("entry")
        profiles = service.list_profiles()
        
        for fp in profiles:
            is_active = fp == app.active_fingerprint
            icon = "■ " if is_active else "□ "
            label = f"{icon}{fp[:12]}..." if len(fp) > 12 else f"{icon}{fp}"
            node = self.root.add(label, data=fp, expand=is_active)
            
            # If this is the active profile or we have the entry service, 
            # we can fetch nested managed accounts.
            if entry_service and is_active:
                # Find managed accounts in the current profile
                # Search for all managed accounts
                managed = entry_service.search_entries("", kinds=["managed_account"])
                for mid, mlabel, _, _, _, _ in managed:
                    node.add_leaf(f"├─ {mlabel}", data=f"managed:{mid}")
                
                # Find agents (nostr)
                agents = entry_service.search_entries("", kinds=["nostr"])
                for aid, alabel, _, _, _, _ in agents:
                    node.add_leaf(f"└─ {alabel}", data=f"agent:{aid}")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle profile selection."""
        value = event.node.data
        if not value or not isinstance(value, str):
            return

        if value.startswith("managed:") or value.startswith("agent:"):
            _, raw_id = value.split(":", 1)
            try:
                entry_id = int(raw_id)
            except ValueError:
                self.app.notify("Invalid tree entry target", severity="error")
                return
            self.app.selected_entry_id = entry_id
            self.app.notify(f"Opened Entry #{entry_id} from profile tree")
            return

        self.app.active_fingerprint = value
        self.app.notify(f"Switched to profile: {value[:8]}")

class SidebarContainer(Static):
    """Container for the sidebar tree and toggle."""
    def compose(self) -> ComposeResult:
        yield Static("PROFILES", id="sidebar-title")
        yield ProfileTree("Profiles", id="profile-tree")

    DEFAULT_CSS = """
    SidebarContainer {
        width: 31;
        background: #0d1114;
        border-right: solid #1a3024;
    }
    #sidebar-title {
        background: #1a3024;
        color: #58f29d;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    #profile-tree {
        background: transparent;
        color: #97b8a6;
        border: none;
        padding: 0;
    }
    #profile-tree > .tree--guides {
        color: #1a3024;
    }
    #profile-tree > .tree--cursor {
        background: #122019;
        color: #58f29d;
        text-style: bold;
    }
    """
