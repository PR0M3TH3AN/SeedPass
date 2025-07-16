import os
import sys

try:
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - Windows only
    msvcrt = None  # type: ignore

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - POSIX only
    termios = None  # type: ignore
    tty = None  # type: ignore


def _masked_input_windows(prompt: str) -> str:
    """Windows implementation using ``msvcrt``."""
    if msvcrt is None:  # pragma: no cover - should not happen
        return input(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    buffer: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            return "".join(buffer)
        if ch in ("\b", "\x7f"):
            if buffer:
                buffer.pop()
                sys.stdout.write("\b \b")
        else:
            buffer.append(ch)
            sys.stdout.write("*")
        sys.stdout.flush()


def _masked_input_posix(prompt: str) -> str:
    """POSIX implementation using ``termios`` and ``tty``."""
    if termios is None or tty is None:  # pragma: no cover - should not happen
        return input(prompt)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buffer: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                return "".join(buffer)
            if ch in ("\x7f", "\b"):
                if buffer:
                    buffer.pop()
                    sys.stdout.write("\b \b")
            else:
                buffer.append(ch)
                sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def masked_input(prompt: str) -> str:
    """Return input from the user while masking typed characters."""
    if sys.platform == "win32":
        return _masked_input_windows(prompt)
    return _masked_input_posix(prompt)
