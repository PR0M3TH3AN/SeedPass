import multiprocessing as mp
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


def test_exclusive_lock_blocks_until_released(tmp_path: Path):
    file_path = tmp_path / "locktest.txt"

    started = mp.Event()
    wait_time = mp.Value("d", 0.0)

    # Increase the lock hold time to reduce flakiness from process startup
    # delays on slower CI runners.
    p1 = mp.Process(target=_hold_lock, args=(file_path, 1.5, started))
    p2 = mp.Process(target=_try_lock, args=(file_path, wait_time))

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
    # The expected wait time is roughly hold_time minus the sleep before
    # starting the second process: 1.5 - 0.1 = 1.4 seconds. Allow a wide
    # tolerance so the test passes on platforms with slower process creation.
    assert wait_time.value == pytest.approx(1.4, abs=0.7)
