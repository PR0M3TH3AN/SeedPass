import sys
from pathlib import Path

import pyotp
from freezegun import freeze_time

sys.path.append(str(Path(__file__).resolve().parents[1]))

from helpers import TEST_SEED
from seedpass.core.totp import TotpManager


@freeze_time("1970-01-01 00:16:40")
def test_current_code_matches_pyotp():
    secret = TotpManager.derive_secret(TEST_SEED, 0)
    expected = pyotp.TOTP(secret).now()
    assert TotpManager.current_code(TEST_SEED, 0) == expected


@freeze_time("1970-01-01 00:00:15")
def test_time_remaining():
    assert TotpManager.time_remaining(period=30) == 15


def test_print_progress_bar_terminates(monkeypatch):
    monkeypatch.setattr(TotpManager, "time_remaining", lambda period: 0)
    calls = []
    monkeypatch.setattr("seedpass.core.totp.time.sleep", lambda s: calls.append(s))
    TotpManager.print_progress_bar(period=30)
    assert calls == []
