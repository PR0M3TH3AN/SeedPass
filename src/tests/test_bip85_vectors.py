import sys
from pathlib import Path
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from local_bip85.bip85 import BIP85

MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

EXPECTED_12 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"

EXPECTED_24 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"

EXPECTED_SYMM_KEY = "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"


@pytest.fixture(scope="module")
def bip85():
    return BIP85(MASTER_XPRV)


def test_bip85_mnemonic_12(bip85):
    assert bip85.derive_mnemonic(index=0, words_num=12) == EXPECTED_12


def test_bip85_mnemonic_24(bip85):
    assert bip85.derive_mnemonic(index=0, words_num=24) == EXPECTED_24


def test_bip85_symmetric_key(bip85):
    assert bip85.derive_symmetric_key(index=0).hex() == EXPECTED_SYMM_KEY


def test_invalid_params(bip85):
    with pytest.raises(SystemExit):
        bip85.derive_mnemonic(index=0, words_num=15)
    with pytest.raises(SystemExit):
        bip85.derive_mnemonic(index=-1, words_num=12)
