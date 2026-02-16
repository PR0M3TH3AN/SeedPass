"""File-based locking utilities using portalocker for cross-platform support."""

from contextlib import contextmanager
from typing import Generator, Optional, Union
from os import PathLike
from pathlib import Path
import portalocker


def _get_portalocker_lock(
    path: Path, flags: int, timeout: Optional[float] = None
) -> portalocker.Lock:
    """Helper to prepare path and create a portalocker.Lock instance."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    kwargs = {
        "mode": "r+b",
        "flags": flags,
    }
    if timeout is not None:
        kwargs["timeout"] = timeout

    return portalocker.Lock(str(path), **kwargs)


@contextmanager
def exclusive_lock(
    path: Union[str, PathLike[str], Path], timeout: Optional[float] = None
) -> Generator[None, None, None]:
    """Context manager that locks *path* exclusively.

    The function opens the file in binary read/write mode and obtains an
    exclusive lock using ``portalocker``. If ``timeout`` is provided,
    acquiring the lock will wait for at most that many seconds before
    raising ``portalocker.exceptions.LockException``.
    """
    path = Path(path)
    lock = _get_portalocker_lock(path, portalocker.LockFlags.EXCLUSIVE, timeout)
    with lock as fh:
        yield fh


@contextmanager
def shared_lock(
    path: Union[str, PathLike[str], Path], timeout: Optional[float] = None
) -> Generator[None, None, None]:
    """Context manager that locks *path* with a shared lock.

    The function opens the file in binary read/write mode and obtains a
    shared lock using ``portalocker``. If ``timeout`` is provided, acquiring
    the lock will wait for at most that many seconds before raising
    ``portalocker.exceptions.LockException``.
    """
    path = Path(path)
    lock = _get_portalocker_lock(path, portalocker.LockFlags.SHARED, timeout)
    with lock as fh:
        fh.seek(0)
        yield fh
