import sys
import select
import io
from typing import Optional


def timed_input(prompt: str, timeout: Optional[float]) -> str:
    """Read input from the user with a timeout."""
    print(prompt, end="", flush=True)
    if timeout is None or timeout <= 0:
        return sys.stdin.readline().strip()
    try:
        sys.stdin.fileno()
    except (AttributeError, io.UnsupportedOperation):
        return input().strip()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    raise TimeoutError("input timed out")
