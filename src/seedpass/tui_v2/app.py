from __future__ import annotations

import importlib.util
from typing import Any


def check_tui2_runtime() -> dict[str, Any]:
    """Return runtime capability diagnostics for TUI v2."""
    textual_available = importlib.util.find_spec("textual") is not None
    return {
        "status": "ok" if textual_available else "unavailable",
        "backend": "textual",
        "textual_available": textual_available,
        "message": (
            "Textual runtime available."
            if textual_available
            else "Textual is not installed. Install `textual` to run tui2."
        ),
    }


def launch_tui2(*, fingerprint: str | None = None) -> bool:
    """Launch TUI v2 when runtime dependencies are available.

    Returns ``True`` when launch succeeds, ``False`` when runtime is unavailable.
    """
    runtime = check_tui2_runtime()
    if not runtime["textual_available"]:
        return False

    # Placeholder shell for incremental migration.
    from textual.app import App, ComposeResult
    from textual.containers import Container
    from textual.widgets import Footer, Header, Static

    class SeedPassTuiV2(App[None]):
        BINDINGS = [("q", "quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Container():
                fp_line = f"Fingerprint: {fingerprint}" if fingerprint else "No fingerprint selected"
                yield Static(
                    "\n".join(
                        [
                            "SeedPass TUI v2 scaffold",
                            fp_line,
                            "",
                            "Next steps:",
                            "- Implement list/search/details panes",
                            "- Add document editor panel",
                            "- Add graph links panel",
                            "",
                            "Press 'q' to quit.",
                        ]
                    )
                )
            yield Footer()

    SeedPassTuiV2().run()
    return True

