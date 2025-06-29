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

    p1 = mp.Process(target=_hold_lock, args=(file_path, 1.0, started))
    p2 = mp.Process(target=_try_lock, args=(file_path, wait_time))

    p1.start()
    started.wait()
    time.sleep(0.1)
    p2.start()

    p1.join()
    p2.join()

    # CI runners can be jittery; allow some slack around the 1s lock hold time
    assert wait_time.value == pytest.approx(1.0, rel=0.2)
