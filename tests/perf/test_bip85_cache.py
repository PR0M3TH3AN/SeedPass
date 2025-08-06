import time

from seedpass.core.manager import PasswordManager


class SlowBIP85:
    """BIP85 stub that simulates a costly derive."""

    def __init__(self):
        self.calls = 0

    def derive_entropy(self, index: int, bytes_len: int, app_no: int = 39) -> bytes:
        self.calls += 1
        time.sleep(0.01)
        return b"\x00" * bytes_len


def _setup_manager(bip85: SlowBIP85) -> PasswordManager:
    pm = PasswordManager.__new__(PasswordManager)
    pm._bip85_cache = {}
    pm.bip85 = bip85
    orig = bip85.derive_entropy

    def cached(index: int, bytes_len: int, app_no: int = 39) -> bytes:
        key = (app_no, index)
        if key not in pm._bip85_cache:
            pm._bip85_cache[key] = orig(index=index, bytes_len=bytes_len, app_no=app_no)
        return pm._bip85_cache[key]

    bip85.derive_entropy = cached
    return pm


def test_bip85_cache_benchmark():
    slow_uncached = SlowBIP85()
    start = time.perf_counter()
    for _ in range(3):
        slow_uncached.derive_entropy(1, 32, 32)
    uncached_time = time.perf_counter() - start

    slow_cached = SlowBIP85()
    pm = _setup_manager(slow_cached)
    start = time.perf_counter()
    for _ in range(3):
        pm.get_bip85_entropy(32, 1)
    cached_time = time.perf_counter() - start

    assert cached_time < uncached_time
    assert slow_uncached.calls == 3
    assert slow_cached.calls == 1
