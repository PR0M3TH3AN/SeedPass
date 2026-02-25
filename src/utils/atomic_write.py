"""Utility helpers for performing atomic file writes.

This module provides a small helper function :func:`atomic_write` which
implements a simple pattern for writing files atomically.  Data is written to a
temporary file in the same directory, flushed and synced to disk, and then
``os.replace`` is used to atomically move the temporary file into place.

The function accepts a callable ``write_func`` that receives the temporary file
object.  This keeps the helper flexible enough to support both text and binary
writes and allows callers to perform complex serialisation steps (e.g. JSON
dumping) without exposing a partially written file to other processes.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Callable, Any, IO


def atomic_write(
    path: str | Path,
    write_func: Callable[[IO[Any]], None],
    *,
    mode: str = "w",
    **open_kwargs: Any,
) -> None:
    """Write to ``path`` atomically using ``write_func``.

    Parameters
    ----------
    path:
        Destination file path.
    write_func:
        Callable that receives an open file object and performs the actual
        write.  The callable should not close the file.
    mode:
        File mode used when opening the temporary file.  Defaults to ``"w"``.
    **open_kwargs:
        Additional keyword arguments passed to :func:`os.fdopen`.
    """

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=str(dest.parent))
    try:
        with os.fdopen(fd, mode, **open_kwargs) as tmp_file:
            write_func(tmp_file)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, dest)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


__all__ = ["atomic_write"]
