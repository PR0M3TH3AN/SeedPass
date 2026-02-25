import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from bip_utils import Bip39SeedGenerator
from local_bip85.bip85 import BIP85
from helpers import TEST_SEED
from seedpass.core.manager import PasswordManager

MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"


def test_init_with_seed_bytes():
    seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
    bip85 = BIP85(seed_bytes)
    assert isinstance(bip85, BIP85)


def test_init_with_xprv():
    bip85 = BIP85(MASTER_XPRV)
    assert isinstance(bip85, BIP85)


def test_initialize_bip85_works_while_locked():
    pm = PasswordManager.__new__(PasswordManager)
    pm.parent_seed = TEST_SEED
    pm.is_locked = True
    pm._bip85_cache = {(39, 0): b"stale"}
    pm.KEY_STORAGE = None
    pm.KEY_INDEX = None
    pm.KEY_PW_DERIVE = None
    pm.KEY_TOTP_DET = None
    pm.master_key = None

    pm.initialize_bip85()

    assert isinstance(pm.bip85, BIP85)
    assert pm._bip85_cache == {}
