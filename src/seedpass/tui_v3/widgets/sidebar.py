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
        profiles = service.list_profiles()
        
        # In v3, we will properly fetch nested accounts. 
        # For this initial scaffold, we populate the top-level fingerprints.
        for fp in profiles:
            icon = "■ " if fp == app.active_fingerprint else "□ "
            label = f"{icon}{fp[:12]}..." if len(fp) > 12 else f"{icon}{fp}"
            node = self.root.add(label, data=fp, expand=True)
            
            # Placeholder for child accounts - in a real run, 
            # we would query the service for sub-entries of this FP.
            # node.add_leaf("  ├─ Managed Account 1")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle profile selection."""
        fp = event.node.data
        if fp and isinstance(fp, str):
            self.app.active_fingerprint = fp
            self.app.notify(f"Switched to profile: {fp[:8]}")

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
