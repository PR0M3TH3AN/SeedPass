import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from bip_utils import Bip39SeedGenerator
from local_bip85.bip85 import BIP85
from helpers import TEST_SEED

MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"


def test_init_with_seed_bytes():
    seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
    bip85 = BIP85(seed_bytes)
    assert isinstance(bip85, BIP85)


def test_init_with_xprv():
    bip85 = BIP85(MASTER_XPRV)
    assert isinstance(bip85, BIP85)
