import threading
import pyperclip


def copy_to_clipboard(text: str, timeout: int) -> None:
    """Copy text to the clipboard and clear after timeout seconds if unchanged."""

    pyperclip.copy(text)

    def clear_clipboard() -> None:
        if pyperclip.paste() == text:
            pyperclip.copy("")

    timer = threading.Timer(timeout, clear_clipboard)
    timer.daemon = True
    timer.start()
