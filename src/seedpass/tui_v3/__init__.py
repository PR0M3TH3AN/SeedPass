from __future__ import annotations
import importlib.util
from typing import Any


def check_tui3_runtime() -> dict[str, Any]:
    """Return runtime capability diagnostics for TUI v3."""
    textual_available = importlib.util.find_spec("textual") is not None
    return {
        "status": "ok" if textual_available else "unavailable",
        "backend": "textual-v3",
        "textual_available": textual_available,
        "message": (
            "Textual runtime available."
            if textual_available
            else "Textual is not installed. Install `textual` to run tui3."
        ),
    }


def launch_tui3(
    *,
    fingerprint: str | None = None,
    entry_service_factory: Any | None = None,
    profile_service_factory: Any | None = None,
    config_service_factory: Any | None = None,
    nostr_service_factory: Any | None = None,
    sync_service_factory: Any | None = None,
    utility_service_factory: Any | None = None,
    vault_service_factory: Any | None = None,
    semantic_service_factory: Any | None = None,
    app_hook: Any | None = None,
) -> bool:
    """Launch TUI v3 from scratch architecture."""
    runtime = check_tui3_runtime()
    if not runtime["textual_available"]:
        return False

    from .app import SeedPassTuiV3

    app = SeedPassTuiV3(
        fingerprint=fingerprint,
        entry_service_factory=entry_service_factory,
        profile_service_factory=profile_service_factory,
        config_service_factory=config_service_factory,
        nostr_service_factory=nostr_service_factory,
        sync_service_factory=sync_service_factory,
        utility_service_factory=utility_service_factory,
        vault_service_factory=vault_service_factory,
        semantic_service_factory=semantic_service_factory,
    )

    if callable(app_hook):
        app_hook(app)
        return True

    app.run()
    return True
