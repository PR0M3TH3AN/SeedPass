"""Clipboard utility helpers."""

import logging
import shutil
import sys
import threading

import pyperclip


class ClipboardUnavailableError(RuntimeError):
    """Raised when required clipboard utilities are not installed."""


logger = logging.getLogger(__name__)


def _ensure_clipboard() -> None:
    """Ensure a clipboard mechanism is available or raise an informative error."""
    try:
        pyperclip.copy("")
    except pyperclip.PyperclipException as exc:
        if sys.platform.startswith("linux"):
            if shutil.which("xclip") is None and shutil.which("xsel") is None:
                raise ClipboardUnavailableError(
                    "Clipboard support requires the 'xclip' package. "
                    "Install it with 'sudo apt install xclip' and restart SeedPass.",
                ) from exc
        raise ClipboardUnavailableError(
            "No clipboard mechanism available. Install a supported clipboard tool or "
            "run SeedPass with --no-clipboard."
        ) from exc


def copy_to_clipboard(text: str, timeout: int) -> bool:
    """Copy text to the clipboard and clear after ``timeout`` seconds if unchanged."""

    _ensure_clipboard()

    pyperclip.copy(text)

    def clear_clipboard() -> None:
        if pyperclip.paste() == text:
            pyperclip.copy("")

    timer = threading.Timer(timeout, clear_clipboard)
    timer.daemon = True
    timer.start()
    return True


__all__ = ["copy_to_clipboard", "ClipboardUnavailableError"]
