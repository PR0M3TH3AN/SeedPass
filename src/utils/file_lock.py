"""File-based locking utilities using portalocker for cross-platform support."""

from contextlib import contextmanager
from typing import Generator, Optional
from pathlib import Path
import portalocker


@contextmanager
def exclusive_lock(
    path: Path, timeout: Optional[float] = None
) -> Generator[None, None, None]:
    """Context manager that locks *path* exclusively.

    The function opens the file in binary append mode and obtains an
    exclusive lock using ``portalocker``. If ``timeout`` is provided,
    acquiring the lock will wait for at most that many seconds before
    raising ``portalocker.exceptions.LockException``.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if timeout is None:
        lock = portalocker.Lock(str(path), mode="a+b")
    else:
        lock = portalocker.Lock(str(path), mode="a+b", timeout=timeout)
    with lock as fh:
        yield fh


@contextmanager
def shared_lock(
    path: Path, timeout: Optional[float] = None
) -> Generator[None, None, None]:
    """Context manager that locks *path* with a shared lock.

    The function opens the file in binary read/write mode and obtains a
    shared lock using ``portalocker``. If ``timeout`` is provided, acquiring
    the lock will wait for at most that many seconds before raising
    ``portalocker.exceptions.LockException``.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    lock = portalocker.Lock(
        str(path), mode="r+b", timeout=timeout, flags=portalocker.LockFlags.SHARED
    )
    with lock as fh:
        fh.seek(0)
        yield fh
