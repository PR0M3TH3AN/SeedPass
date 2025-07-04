import threading
import logging
import subprocess
import shutil
import sys

import pyperclip

logger = logging.getLogger(__name__)


def _ensure_clipboard() -> None:
    """Attempt to ensure a clipboard mechanism is available."""
    try:
        pyperclip.copy("")
    except pyperclip.PyperclipException as exc:
        if sys.platform.startswith("linux"):
            if shutil.which("xclip") is None and shutil.which("xsel") is None:
                apt = shutil.which("apt-get") or shutil.which("apt")
                if apt:
                    try:
                        subprocess.run(
                            ["sudo", apt, "install", "-y", "xclip"], check=True
                        )
                        pyperclip.copy("")
                        return
                    except Exception as install_exc:  # pragma: no cover - system dep
                        logger.warning(
                            "Automatic xclip installation failed: %s", install_exc
                        )
        raise exc


def copy_to_clipboard(text: str, timeout: int) -> None:
    """Copy text to the clipboard and clear after timeout seconds if unchanged."""

    _ensure_clipboard()
    pyperclip.copy(text)

    def clear_clipboard() -> None:
        if pyperclip.paste() == text:
            pyperclip.copy("")

    timer = threading.Timer(timeout, clear_clipboard)
    timer.daemon = True
    timer.start()
