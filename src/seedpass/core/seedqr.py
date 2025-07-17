"""SeedQR encoding utilities."""

from __future__ import annotations

from bip_utils.bip.bip39.bip39_mnemonic import Bip39Languages
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter


def encode_seedqr(mnemonic: str) -> str:
    """Return SeedQR digit stream for a BIP-39 mnemonic."""
    wordlist = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)
    words = mnemonic.strip().split()
    indices = [wordlist.GetWordIdx(word.lower()) for word in words]
    return "".join(f"{idx:04d}" for idx in indices)
