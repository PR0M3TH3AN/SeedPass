from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Button
from textual.containers import Vertical, Horizontal

from .maintenance import MAINTENANCE_CSS


def render_wayfinder(payload: dict) -> str:
    scope_path = str(payload.get("scope_path", "unknown"))
    stats = payload.get("stats", {}) or {}
    counts = ((payload.get("counts_by_kind") or {}).get("data") or {}).get("counts", {})
    children = ((payload.get("children_of") or {}).get("data") or {}).get(
        "children", []
    )
    recent = ((payload.get("recent_activity") or {}).get("data") or {}).get("items", [])

    lines = [
        f"Scope: {scope_path}",
        f"Events: {int(stats.get('event_count', 0))}  Checkpoints: {int(stats.get('checkpoint_count', 0))}  Views: {int(stats.get('writer_count', 0))} writers",
        "",
        "Counts By Kind:",
    ]
    if counts:
        for kind, count in sorted(counts.items()):
            lines.append(f"- {kind}: {count}")
    else:
        lines.append("- No entries indexed")
    lines.append("")
    lines.append("Children:")
    if children:
        for child in children[:12]:
            archived = " [archived]" if child.get("archived") else ""
            lines.append(
                f"- #{child.get('entry_id')} {child.get('label') or '(unnamed)'} ({child.get('kind')}){archived}"
            )
    else:
        lines.append("- No children")
    lines.append("")
    lines.append("Recent Activity:")
    if recent:
        for item in recent[:10]:
            summary = str(item.get("summary", "")).strip()
            suffix = f" :: {summary}" if summary else ""
            lines.append(
                f"- {item.get('event_type')} #{item.get('subject_id')} ({item.get('subject_kind')}){suffix}"
            )
    else:
        lines.append("- No recent activity")
    return "\n".join(lines)


class AtlasWayfinderScreen(Screen):
    CSS = MAINTENANCE_CSS + """
    #atlas-wayfinder-shell { background: #101010; }
    #atlas-wayfinder-actions {
        height: auto;
        margin: 0 2;
    }
    #atlas-wayfinder-actions Button {
        margin-right: 1;
        margin-bottom: 1;
    }
    #atlas-wayfinder-content {
        padding: 1 2;
        border: heavy #000000;
        background: #f4f4f4;
        color: #000000;
        margin: 1 2;
    }
    """

    def __init__(self, payload: dict) -> None:
        super().__init__()
        self.payload = payload

    def compose(self) -> ComposeResult:
        children = ((self.payload.get("children_of") or {}).get("data") or {}).get(
            "children", []
        )
        recent = ((self.payload.get("recent_activity") or {}).get("data") or {}).get(
            "items", []
        )
        with Vertical(id="atlas-wayfinder-shell"):
            yield Static("SeedPass ◈ Atlas Wayfinder", classes="maintenance-title")
            yield Static(
                "Index0 atlas views for the active scope. This is a synced navigation summary, not a separate database.",
                classes="maintenance-intro-dark",
            )
            with Horizontal(id="atlas-wayfinder-actions"):
                yield Button("All", id="atlas-filter-all", variant="default")
                yield Button("Docs", id="atlas-filter-docs", variant="default")
                yield Button("Secrets", id="atlas-filter-secrets", variant="default")
                if children:
                    first_child = children[0]
                    yield Button(
                        f"Open #{first_child.get('entry_id')}",
                        id=f"atlas-open-entry-{first_child.get('entry_id')}",
                        variant="primary",
                    )
                if recent:
                    recent_subject = recent[0].get("subject_id")
                    if recent_subject:
                        yield Button(
                            f"Open Recent #{recent_subject}",
                            id=f"atlas-open-recent-{recent_subject}",
                            variant="default",
                        )
            yield Static(render_wayfinder(self.payload), id="atlas-wayfinder-content")
            yield Static(
                "ESC: Back | ctrl+p: Palette | Buttons jump into entries and filters",
                classes="maintenance-footer",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "atlas-filter-all":
            self.app.action_set_kind_filter("all")
            self.app.pop_screen()
            return
        if button_id == "atlas-filter-docs":
            self.app.action_set_kind_filter("docs")
            self.app.pop_screen()
            return
        if button_id == "atlas-filter-secrets":
            self.app.action_set_kind_filter("secrets")
            self.app.pop_screen()
            return
        if button_id.startswith("atlas-open-entry-"):
            try:
                entry_id = int(button_id.removeprefix("atlas-open-entry-"))
            except ValueError:
                return
            self.app.selected_entry_id = entry_id
            self.app.pop_screen()
            return
        if button_id.startswith("atlas-open-recent-"):
            try:
                entry_id = int(button_id.removeprefix("atlas-open-recent-"))
            except ValueError:
                return
            self.app.selected_entry_id = entry_id
            self.app.pop_screen()
