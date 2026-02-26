import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).resolve().parents[2] / "src"))

from bip_utils import Bip39SeedGenerator  # noqa: E402
from local_bip85.bip85 import BIP85  # noqa: E402

# Known test vector for:
# "abandon abandon abandon abandon abandon abandon abandon abandon abandon
# abandon abandon about"
# Derived with app_no=2, index=0, entropy_bytes=32
KNOWN_SYMMETRIC_KEY_HEX = (
    "f8c4bd4d57899c08b083e5d999c5041e1cd05bf6a6cded6e382bd231839cd2d8"
)
TEST_SEED_PHRASE = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)


def test_bip85_symmetric_key_stability():
    """
    Verifies that the BIP85 symmetric key derivation remains stable.
    This test ensures that the custom use of app_no=2 for symmetric keys
    does not change unexpectedly.
    """
    seed_bytes = Bip39SeedGenerator(TEST_SEED_PHRASE).Generate()
    bip85 = BIP85(seed_bytes)
    key = bip85.derive_symmetric_key(index=0, app_no=2)
    assert key.hex() == KNOWN_SYMMETRIC_KEY_HEX


def test_bip85_app_no_39_default_behavior():
    """
    Verifies the behavior when app_no=39 is used directly with derive_entropy.
    The implementation currently defaults word_count to entropy_bytes if
    not provided. This test documents this behavior to detect
    regression/changes.
    """
    seed_bytes = Bip39SeedGenerator(TEST_SEED_PHRASE).Generate()
    bip85 = BIP85(seed_bytes)

    # Requesting 16 bytes (128 bits) with app_no=39
    # If word_count is None, it defaults to 16.
    # Path becomes m/83696968'/39'/0'/16'/0'
    entropy = bip85.derive_entropy(index=0, entropy_bytes=16, app_no=39)
    assert len(entropy) == 16

    # Verify it is DIFFERENT from explicit 12 words
    # (which uses path .../12'/...)
    entropy_12_words = bip85.derive_entropy(
        index=0, entropy_bytes=16, app_no=39, word_count=12
    )
    assert entropy != entropy_12_words
