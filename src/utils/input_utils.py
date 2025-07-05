import sys
import select
import io
import time
from typing import Optional

try:
    import msvcrt
except ImportError:  # pragma: no cover - not on Windows
    msvcrt = None


def _timed_input_posix(timeout: float) -> str:
    """POSIX implementation of timed input using ``select``."""
    try:
        sys.stdin.fileno()
    except (AttributeError, io.UnsupportedOperation):
        return input().strip()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    raise TimeoutError("input timed out")


def _timed_input_windows(timeout: float) -> str:
    """Windows implementation of timed input using ``msvcrt``."""
    if msvcrt is None:  # pragma: no cover - should not happen
        return input().strip()
    start = time.time()
    buffer: list[str] = []
    while True:
        if msvcrt.kbhit():
            char = msvcrt.getwche()
            if char in ("\r", "\n"):
                print()
                return "".join(buffer)
            if char == "\b":
                if buffer:
                    buffer.pop()
                    print("\b \b", end="", flush=True)
            else:
                buffer.append(char)
        if (time.time() - start) > timeout:
            raise TimeoutError("input timed out")
        time.sleep(0.05)


def timed_input(prompt: str, timeout: Optional[float]) -> str:
    """Read input from the user with a timeout."""
    print(prompt, end="", flush=True)
    if timeout is None or timeout <= 0:
        return sys.stdin.readline().strip()

    if sys.platform == "win32":
        return _timed_input_windows(timeout)

    # Fallback to ``select``-based implementation for POSIX systems
    return _timed_input_posix(timeout)
