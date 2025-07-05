import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from utils.file_lock import exclusive_lock


def _hold_lock(path: Path, hold_time: float, started: mp.Event):
    with exclusive_lock(path):
        started.set()
        time.sleep(hold_time)


def _try_lock(path: Path, wait_time: mp.Value):
    t0 = time.perf_counter()
    with exclusive_lock(path):
        wait_time.value = time.perf_counter() - t0


@pytest.mark.skipif(
    os.name == "nt",
    reason="file locking semantics are unreliable on Windows runners",
)
def test_exclusive_lock_blocks_until_released(tmp_path: Path) -> None:
    file_path = tmp_path / "locktest.txt"

    # Use 'fork' start method when available for more deterministic timing on
    # platforms like macOS where the default 'spawn' method can delay process
    # startup significantly.
    if "fork" in mp.get_all_start_methods():
        ctx = mp.get_context("fork")
    else:
        ctx = mp.get_context()

    started = ctx.Event()
    wait_time = ctx.Value("d", 0.0)

    p1 = ctx.Process(target=_hold_lock, args=(file_path, 1.0, started))
    p2 = ctx.Process(target=_try_lock, args=(file_path, wait_time))

    p1.start()
    started.wait()
    time.sleep(0.1)
    p2.start()

    p1.join()
    p2.join()

    # CI runners can be jittery; allow generous slack around the 1s lock hold time
    # Different operating systems spawn processes at slightly different speeds
    # which can shift the measured wait time by a few hundred milliseconds. A
    # wider tolerance keeps the test stable across platforms.
    assert wait_time.value == pytest.approx(1.0, abs=0.7)
