import logging
import shutil
import sys
import threading

import pyperclip

logger = logging.getLogger(__name__)


def _ensure_clipboard() -> None:
    """Ensure a clipboard mechanism is available or raise an informative error."""
    try:
        pyperclip.copy("")
    except pyperclip.PyperclipException as exc:
        if sys.platform.startswith("linux"):
            if shutil.which("xclip") is None and shutil.which("xsel") is None:
                raise pyperclip.PyperclipException(
                    "Clipboard support requires the 'xclip' package. "
                    "Install it with 'sudo apt install xclip' and restart SeedPass."
                ) from exc
        raise


def copy_to_clipboard(text: str, timeout: int) -> bool:
    """Copy text to the clipboard and clear after timeout seconds if unchanged.

    Returns True if the text was successfully copied, False otherwise.
    """

    try:
        _ensure_clipboard()
    except pyperclip.PyperclipException as exc:
        warning = (
            "Clipboard unavailable: "
            + str(exc)
            + "\nSeedPass secret mode requires clipboard support. "
            "Install xclip or disable secret mode to view secrets."
        )
        logger.warning(warning)
        print(warning)
        return False

    pyperclip.copy(text)

    def clear_clipboard() -> None:
        if pyperclip.paste() == text:
            pyperclip.copy("")

    timer = threading.Timer(timeout, clear_clipboard)
    timer.daemon = True
    timer.start()
    return True
