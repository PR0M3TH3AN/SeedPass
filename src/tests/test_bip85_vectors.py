import sys
from pathlib import Path
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from local_bip85.bip85 import BIP85, Bip85Error
from seedpass.core.password_generation import (
    derive_ssh_key,
    derive_seed_phrase,
)
from utils.key_derivation import derive_totp_secret

MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

EXPECTED_12 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"

EXPECTED_24 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"

EXPECTED_SYMM_KEY = "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"
EXPECTED_TOTP_SECRET = "VQYTWDNEWYBY2G3LOGGCEKR4LZ3LNEYY"
EXPECTED_SSH_KEY = "52405cd0dd21c5be78314a7c1a3c65ffd8d896536cc7dee3157db5824f0c92e2"


@pytest.fixture(scope="module")
def bip85():
    return BIP85(MASTER_XPRV)


def test_bip85_mnemonic_12(bip85):
    assert bip85.derive_mnemonic(index=0, words_num=12) == EXPECTED_12


def test_bip85_mnemonic_24(bip85):
    assert bip85.derive_mnemonic(index=0, words_num=24) == EXPECTED_24


def test_bip85_symmetric_key(bip85):
    assert bip85.derive_symmetric_key(index=0).hex() == EXPECTED_SYMM_KEY


def test_derive_totp_secret():
    assert derive_totp_secret(EXPECTED_24, 0) == EXPECTED_TOTP_SECRET


def test_derive_ssh_key(bip85):
    assert derive_ssh_key(bip85, 0).hex() == EXPECTED_SSH_KEY


def test_derive_seed_phrase(bip85):
    assert derive_seed_phrase(bip85, 0) == EXPECTED_24


def test_invalid_params(bip85):
    with pytest.raises(Bip85Error):
        bip85.derive_mnemonic(index=0, words_num=15)
    with pytest.raises(Bip85Error):
        bip85.derive_mnemonic(index=-1, words_num=12)
