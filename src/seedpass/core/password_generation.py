# seedpass.core/password_generation.py

"""
Password Generation Module

This module provides the PasswordGenerator class responsible for deterministic password generation
based on a BIP-39 parent seed. It leverages BIP-85 for entropy derivation and ensures that
generated passwords meet complexity requirements.

Ensure that all dependencies are installed and properly configured in your environment.

Never ever ever use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed.
This means it should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this software's use case.
To keep behaviour stable across Python versions, the shuffling logic uses an
HMAC-SHA256-based Fisher–Yates shuffle instead of ``random.Random``. The HMAC
is keyed with the derived password bytes, providing deterministic yet
cryptographically strong pseudo-randomness without relying on Python's
non-stable random implementation.
"""

import os
import logging
import hashlib
import string
import hmac
import base64
from typing import Optional
from dataclasses import dataclass
from termcolor import colored
from pathlib import Path
import shutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from bip_utils import Bip39SeedGenerator

from . import compat  # noqa: F401
from local_bip85.bip85 import BIP85

from constants import (
    DEFAULT_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    SAFE_SPECIAL_CHARS,
)
from .encryption import EncryptionManager

# Instantiate the logger
logger = logging.getLogger(__name__)


@dataclass
class PasswordPolicy:
    """Minimum complexity requirements for generated passwords.

    Attributes:
        min_uppercase: Minimum required uppercase letters.
        min_lowercase: Minimum required lowercase letters.
        min_digits: Minimum required digits.
        min_special: Minimum required special characters.
        include_special_chars: Whether to include any special characters.
        allowed_special_chars: Explicit set of allowed special characters.
        special_mode: Preset mode for special characters (e.g. "safe").
        exclude_ambiguous: Exclude easily confused characters like ``O`` and ``0``.
    """

    min_uppercase: int = 2
    min_lowercase: int = 2
    min_digits: int = 2
    min_special: int = 2
    include_special_chars: bool = True
    allowed_special_chars: str | None = None
    special_mode: str | None = None
    exclude_ambiguous: bool = False


# Generation versions. Entries record which one produced them; absent means 1.
#
# v1 -- the original algorithm. Frozen forever: passwords are re-derived on
#       demand and never stored, so every live vault entry depends on it
#       reproducing byte-identically. Pinned by
#       src/tests/test_entropy_integrity.py::test_v1_password_vectors_are_frozen.
# v2 -- drops the forced equal-quarters class quota, uses rejection sampling to
#       remove modulo bias, and draws from an unbounded HMAC-expanded stream.
LEGACY_PASSWORD_GEN_VERSION = 1
CURRENT_PASSWORD_GEN_VERSION = 2


class DeterministicStream:
    """Byte stream for v1: cycles ``dk`` with wraparound.

    Retained unchanged because v1 output depends on it, including the
    wraparound. v2 uses :class:`ExpandedStream` instead -- wrapping a fixed key
    is a repeating pad, not a stream.
    """

    def __init__(self, dk: bytes):
        self.dk = dk
        self.index = 0
        self.length = len(dk)

    def get_value(self) -> int:
        value = self.dk[self.index % self.length]
        self.index += 1
        return value

    @property
    def current_index(self) -> int:
        return self.index


class ExpandedStream:
    """Unbounded deterministic byte stream for v2 (audit item M3).

    Generates SHA-256 blocks on demand as ``HMAC(dk, info || counter)`` rather
    than cycling a fixed 32-byte key, so it never repeats within any usable
    password length. ``info`` domain-separates independent streams derived from
    the same ``dk``.
    """

    def __init__(self, dk: bytes, info: bytes = b""):
        self._key = dk
        self._info = info
        self._block = b""
        self._pos = 0
        self._counter = 0

    def get_value(self) -> int:
        if self._pos >= len(self._block):
            msg = self._info + self._counter.to_bytes(4, "big")
            self._block = hmac.new(self._key, msg, hashlib.sha256).digest()
            self._counter += 1
            self._pos = 0
        value = self._block[self._pos]
        self._pos += 1
        return value


def _uniform_index(stream, max_exclusive: int) -> int:
    """Uniform value in ``[0, max_exclusive)`` by rejection sampling.

    Avoids the modulo bias in ``byte % len(alphabet)`` (audit item M2): with a
    94-character alphabet, plain modulo gives 68 characters probability 3/256
    and the other 26 only 2/256. Requires an unbounded stream, since rejection
    consumes a variable number of bytes -- hence :class:`ExpandedStream`.
    """
    if max_exclusive <= 0:
        raise ValueError("max_exclusive must be positive")
    if max_exclusive > 256:
        raise ValueError("_uniform_index supports single-byte ranges only")
    limit = 256 - (256 % max_exclusive)
    while True:
        value = stream.get_value()
        if value < limit:
            return value % max_exclusive


class PasswordGenerator:
    """
    PasswordGenerator Class

    Responsible for deterministic password generation based on a BIP-39 parent seed.
    Utilizes BIP-85 for entropy derivation and ensures that generated passwords meet
    complexity requirements.
    """

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        parent_seed: str,
        bip85: BIP85,
        policy: PasswordPolicy | None = None,
    ):
        """
        Initializes the PasswordGenerator with the encryption manager, parent seed, and BIP85 instance.

        Parameters:
            encryption_manager (EncryptionManager): The encryption manager instance.
            parent_seed (str): The BIP-39 parent seed phrase.
            bip85 (BIP85): The BIP85 instance for generating deterministic entropy.
        """
        try:
            self.encryption_manager = encryption_manager
            self.parent_seed = parent_seed
            self.bip85 = bip85
            self.policy = policy or PasswordPolicy()

            if isinstance(parent_seed, (bytes, bytearray)):
                self.seed_bytes = bytes(parent_seed)
            else:
                self.seed_bytes = self.encryption_manager.derive_seed_from_mnemonic(
                    self.parent_seed
                )

            logger.debug("PasswordGenerator initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize PasswordGenerator: {e}", exc_info=True)
            print(colored(f"Error: Failed to initialize PasswordGenerator: {e}", "red"))
            raise

    def _derive_password_entropy(self, index: int) -> bytes:
        """Derive deterministic entropy for password generation.

        Chain: BIP-85 (64 bytes, app_no=32) -> PBKDF2-HMAC-SHA256 (empty salt,
        100k iterations) -> 32-byte derived key.

        The empty salt is deliberate: a random salt would break the determinism
        this whole module exists to provide (see the module docstring). The
        iteration count is not doing password-stretching work here -- the input
        is already 64 bytes of high-entropy BIP-85 output, not a human secret.
        """
        entropy = self.bip85.derive_entropy(index=index, entropy_bytes=64, app_no=32)
        logger.debug("Entropy derived for password generation.")

        dk = hashlib.pbkdf2_hmac("sha256", entropy, b"", 100000)
        logger.debug("Derived key using PBKDF2.")
        return dk

    def _map_entropy_to_chars(self, dk: bytes, alphabet: str) -> str:
        """Map derived bytes to characters from the provided alphabet."""
        password = "".join(alphabet[byte % len(alphabet)] for byte in dk)
        logger.debug("Mapped entropy to allowed characters.")
        return password

    def _fisher_yates_hmac(self, items: list[str], key: bytes) -> list[str]:
        """Shuffle ``items`` in a deterministic yet cryptographically sound manner.

        A Fisher–Yates shuffle is driven by an HMAC-SHA256 based
        pseudo-random number generator seeded with ``key``.  Unlike
        :class:`random.Random`, this approach is stable across Python
        versions while still deriving all of its entropy from ``key``.
        """

        counter = 0
        for i in range(len(items) - 1, 0, -1):
            msg = counter.to_bytes(4, "big")
            digest = hmac.new(key, msg, hashlib.sha256).digest()
            j = int.from_bytes(digest, "big") % (i + 1)
            items[i], items[j] = items[j], items[i]
            counter += 1
        return items

    def _shuffle_deterministically(self, password: str, dk: bytes) -> str:
        """Deterministically shuffle characters using an HMAC-based PRNG."""

        password_chars = list(password)
        shuffled_chars = self._fisher_yates_hmac(password_chars, dk)
        shuffled = "".join(shuffled_chars)
        logger.debug("Shuffled password deterministically using HMAC-Fisher-Yates.")
        return shuffled

    def generate_password(
        self,
        length: int = DEFAULT_PASSWORD_LENGTH,
        index: int = 0,
        gen_version: int = LEGACY_PASSWORD_GEN_VERSION,
    ) -> str:
        """
        Generates a deterministic password based on the parent seed, desired length, and index.

        Common to both versions:
        1. Derive entropy using BIP-85.
        2. Use PBKDF2-HMAC-SHA256 to derive a 32-byte key from that entropy.

        Version 1 (default, frozen) then:
        3. Maps derived bytes to characters with ``byte % len(alphabet)``.
        4. Enforces minimum counts, adds symbols, and forces an equal quota of
           each character class across the whole password.
        5. Shuffles, extends/trims to length, re-enforces, shuffles again.

        Version 2 then:
        3. Draws exactly ``length`` characters by rejection sampling from an
           unbounded HMAC-expanded stream (no modulo bias, no repeating pad).
        4. Enforces only the policy minima, without pinning the composition.
        5. Shuffles once.

        ``gen_version`` defaults to 1 so that every caller which does not
        explicitly opt in keeps deriving exactly what it derived before. Entry
        records carry the version; see ``_generate_password_for_entry``.

        Parameters:
            length (int): Desired length of the password.
            index (int): Index for deriving child entropy.
            gen_version (int): Generation algorithm version (1 or 2).

        Returns:
            str: The generated password.
        """
        try:
            # Validate password length
            if length < MIN_PASSWORD_LENGTH:
                logger.error(
                    f"Password length must be at least {MIN_PASSWORD_LENGTH} characters."
                )
                raise ValueError(
                    f"Password length must be at least {MIN_PASSWORD_LENGTH} characters."
                )
            if length > MAX_PASSWORD_LENGTH:
                logger.error(
                    f"Password length must not exceed {MAX_PASSWORD_LENGTH} characters."
                )
                raise ValueError(
                    f"Password length must not exceed {MAX_PASSWORD_LENGTH} characters."
                )

            dk = self._derive_password_entropy(index=index)
            all_allowed, allowed_special = self._alphabets()

            if gen_version == CURRENT_PASSWORD_GEN_VERSION:
                return self._generate_password_v2(
                    length, dk, all_allowed, allowed_special
                )
            if gen_version != LEGACY_PASSWORD_GEN_VERSION:
                raise ValueError(
                    f"Unknown password generation version: {gen_version!r}"
                )

            password = self._map_entropy_to_chars(dk, all_allowed)
            password = self._enforce_complexity(
                password, all_allowed, allowed_special, dk
            )
            password = self._shuffle_deterministically(password, dk)

            # Ensure password length by extending if necessary
            if len(password) < length:
                while len(password) < length:
                    dk = hashlib.pbkdf2_hmac("sha256", dk, b"", 1)
                    extra = self._map_entropy_to_chars(dk, all_allowed)
                    password += extra
                    password = self._shuffle_deterministically(password, dk)
                    logger.debug("Extended password to meet length requirement.")

            # Trim the password to the desired length and enforce complexity on
            # the final result. Complexity enforcement is repeated here because
            # trimming may remove required character classes from the password
            # produced above when the requested length is shorter than the
            # initial entropy size.
            password = password[:length]
            password = self._enforce_complexity(
                password, all_allowed, allowed_special, dk
            )
            password = self._shuffle_deterministically(password, dk)
            logger.debug(
                f"Generated final password of length {length} with complexity enforced."
            )

            return password

        except Exception as e:
            logger.error(f"Error generating password: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate password: {e}", "red"))
            raise

    def _alphabets(self) -> tuple[str, str]:
        """Return ``(all_allowed, allowed_special)`` for the active policy."""
        letters = string.ascii_letters
        digits = string.digits

        if self.policy.exclude_ambiguous:
            ambiguous = "O0Il1"
            letters = "".join(c for c in letters if c not in ambiguous)
            digits = "".join(c for c in digits if c not in ambiguous)

        if not self.policy.include_special_chars:
            allowed_special = ""
        elif self.policy.allowed_special_chars is not None:
            allowed_special = self.policy.allowed_special_chars
        elif self.policy.special_mode == "safe":
            allowed_special = SAFE_SPECIAL_CHARS
        else:
            allowed_special = string.punctuation

        return letters + digits + allowed_special, allowed_special

    def _class_sets(self, allowed_special: str) -> dict[str, str]:
        """Character class -> its allowed members under the active policy."""
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        if self.policy.exclude_ambiguous:
            ambiguous = "O0Il1"
            uppercase = "".join(c for c in uppercase if c not in ambiguous)
            lowercase = "".join(c for c in lowercase if c not in ambiguous)
            digits = "".join(c for c in digits if c not in ambiguous)
        return {
            "upper": uppercase,
            "lower": lowercase,
            "digit": digits,
            "special": allowed_special,
        }

    def _generate_password_v2(
        self, length: int, dk: bytes, all_allowed: str, allowed_special: str
    ) -> str:
        """Version 2 generation (audit items M1, M2, M3).

        Unlike v1 this does not pin the character-class composition. v1 forced
        exactly ``length/4`` of each class into every password, which cost
        5.7-11.5 bits over the usable length range and made any SeedPass
        password recognisable by its composition alone. v2 enforces only what
        the policy actually asks for.
        """
        class_sets = self._class_sets(allowed_special)
        minima = {
            "upper": self.policy.min_uppercase,
            "lower": self.policy.min_lowercase,
            "digit": self.policy.min_digits,
            "special": self.policy.min_special if allowed_special else 0,
        }
        # Drop classes the policy excludes entirely, so they are never required
        # and never counted as donors.
        minima = {k: v for k, v in minima.items() if class_sets[k]}

        required = sum(minima.values())
        if required > length:
            raise ValueError(
                f"Policy requires at least {required} characters "
                f"({', '.join(f'{v} {k}' for k, v in minima.items() if v)}) "
                f"but the requested length is {length}."
            )

        char_stream = ExpandedStream(dk, b"seedpass-v2-chars")
        policy_stream = ExpandedStream(dk, b"seedpass-v2-policy")

        chars = [
            all_allowed[_uniform_index(char_stream, len(all_allowed))]
            for _ in range(length)
        ]

        self._enforce_minima_v2(chars, policy_stream, class_sets, minima)

        shuffle_key = hmac.new(dk, b"seedpass-v2-shuffle", hashlib.sha256).digest()
        chars = self._fisher_yates_hmac(chars, shuffle_key)
        return "".join(chars)

    @staticmethod
    def _classify(char: str, class_sets: dict[str, str]) -> str | None:
        for name, members in class_sets.items():
            if char in members:
                return name
        return None

    def _enforce_minima_v2(
        self,
        chars: list[str],
        stream: "ExpandedStream",
        class_sets: dict[str, str],
        minima: dict[str, int],
    ) -> None:
        """Raise deficient classes to their minimum without breaking others.

        v1's ``_enforce_minimum_counts`` overwrites uniformly random positions,
        so satisfying one minimum could destroy another; v1 got away with it
        only because ``_balance_distribution`` then rewrote nearly every
        position anyway. v2 has no such backstop, so donor positions are chosen
        only from classes that currently have a surplus.
        """
        counts = {name: 0 for name in class_sets}
        for char in chars:
            name = self._classify(char, class_sets)
            if name is not None:
                counts[name] += 1

        for name, minimum in minima.items():
            while counts[name] < minimum:
                donors = [
                    i
                    for i, char in enumerate(chars)
                    if (other := self._classify(char, class_sets)) != name
                    and other is not None
                    and counts[other] > minima.get(other, 0)
                ]
                if not donors:
                    # Unreachable while sum(minima) <= length, which the caller
                    # enforces; kept so a future policy change fails loudly.
                    raise ValueError(
                        f"Cannot satisfy minimum for {name!r} without violating "
                        f"another policy minimum."
                    )
                position = donors[_uniform_index(stream, len(donors))]
                donor_class = self._classify(chars[position], class_sets)
                members = class_sets[name]
                chars[position] = members[_uniform_index(stream, len(members))]
                counts[donor_class] -= 1
                counts[name] += 1

    def _count_char_types(
        self,
        password_chars: list[str],
        uppercase: str,
        lowercase: str,
        digits: str,
        special: str,
    ) -> tuple[int, int, int, int]:
        """Count the occurrences of each character type in the password."""
        upper = sum(1 for c in password_chars if c in uppercase)
        lower = sum(1 for c in password_chars if c in lowercase)
        digs = sum(1 for c in password_chars if c in digits)
        specs = sum(1 for c in password_chars if c in special)
        return upper, lower, digs, specs

    def _enforce_minimum_counts(
        self,
        password_chars: list[str],
        stream: DeterministicStream,
        uppercase: str,
        lowercase: str,
        digits: str,
        special: str,
        counts: tuple[int, int, int, int],
    ):
        """Replace characters to meet minimum counts."""
        current_upper, current_lower, current_digits, current_special = counts
        min_upper = self.policy.min_uppercase
        min_lower = self.policy.min_lowercase
        min_digits = self.policy.min_digits
        min_special = self.policy.min_special if special else 0

        if current_upper < min_upper:
            for _ in range(min_upper - current_upper):
                index = stream.get_value() % len(password_chars)
                char = uppercase[stream.get_value() % len(uppercase)]
                password_chars[index] = char
                logger.debug(f"Added uppercase letter at position {index}.")

        if current_lower < min_lower:
            for _ in range(min_lower - current_lower):
                index = stream.get_value() % len(password_chars)
                char = lowercase[stream.get_value() % len(lowercase)]
                password_chars[index] = char
                logger.debug(f"Added lowercase letter at position {index}.")

        if current_digits < min_digits:
            for _ in range(min_digits - current_digits):
                index = stream.get_value() % len(password_chars)
                char = digits[stream.get_value() % len(digits)]
                password_chars[index] = char
                logger.debug(f"Added digit at position {index}.")

        if special and current_special < min_special:
            for _ in range(min_special - current_special):
                index = stream.get_value() % len(password_chars)
                char = special[stream.get_value() % len(special)]
                password_chars[index] = char
                logger.debug(f"Added special character at position {index}.")

    def _add_additional_symbols(
        self, password_chars: list[str], stream: DeterministicStream, special: str
    ):
        """Additional deterministic inclusion of symbols to increase score."""
        if special:
            symbol_target = 3  # Increase target number of symbols
            current_symbols = sum(1 for c in password_chars if c in special)
            additional_symbols_needed = max(symbol_target - current_symbols, 0)

            for _ in range(additional_symbols_needed):
                # Avoid exceeding the derived key length (stream handles modulo internally,
                # but we respect the original logic's intent if it was length-bound,
                # however, stream wraps around naturally based on DK length.
                # Original code broke loop if index >= length.
                # We can check stream.current_index relative to stream.length.
                if stream.current_index >= stream.length:
                    break
                index = stream.get_value() % len(password_chars)
                char = special[stream.get_value() % len(special)]
                password_chars[index] = char
                logger.debug(f"Added additional symbol at position {index}.")

    def _balance_distribution(
        self,
        password_chars: list[str],
        stream: DeterministicStream,
        uppercase: str,
        lowercase: str,
        digits: str,
        special: str,
    ):
        """Ensure balanced distribution by assigning different character types to specific segments."""
        char_types = [uppercase, lowercase, digits]
        if special:
            char_types.append(special)

        segment_length = len(password_chars) // len(char_types)
        if segment_length > 0:
            for i, char_type in enumerate(char_types):
                segment_start = i * segment_length
                segment_end = segment_start + segment_length
                if segment_end > len(password_chars):
                    segment_end = len(password_chars)
                for j in range(segment_start, segment_end):
                    if i == 0 and password_chars[j] not in uppercase:
                        char = uppercase[stream.get_value() % len(uppercase)]
                        password_chars[j] = char
                        logger.debug(f"Assigned uppercase letter to position {j}.")
                    elif i == 1 and password_chars[j] not in lowercase:
                        char = lowercase[stream.get_value() % len(lowercase)]
                        password_chars[j] = char
                        logger.debug(f"Assigned lowercase letter to position {j}.")
                    elif i == 2 and password_chars[j] not in digits:
                        char = digits[stream.get_value() % len(digits)]
                        password_chars[j] = char
                        logger.debug(f"Assigned digit to position {j}.")
                    elif (
                        special
                        and i == len(char_types) - 1
                        and password_chars[j] not in special
                    ):
                        char = special[stream.get_value() % len(special)]
                        password_chars[j] = char
                        logger.debug(f"Assigned special character to position {j}.")

    def _enforce_complexity(
        self, password: str, alphabet: str, allowed_special: str, dk: bytes
    ) -> str:
        """
        Ensures that the password contains at least two uppercase letters, two lowercase letters,
        two digits, and two special characters, modifying it deterministically if necessary.
        Also balances the distribution of character types.

        Parameters:
            password (str): The initial password.
            alphabet (str): Allowed characters in the password.
            dk (bytes): Derived key used for deterministic modifications.

        Returns:
            str: Password that meets complexity requirements.
        """
        try:
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            special = allowed_special

            if self.policy.exclude_ambiguous:
                ambiguous = "O0Il1"
                uppercase = "".join(c for c in uppercase if c not in ambiguous)
                lowercase = "".join(c for c in lowercase if c not in ambiguous)
                digits = "".join(c for c in digits if c not in ambiguous)

            password_chars = list(password)

            # Count initial character types
            counts = self._count_char_types(
                password_chars, uppercase, lowercase, digits, special
            )
            logger.debug(
                f"Current character counts - Upper: {counts[0]}, Lower: {counts[1]}, Digits: {counts[2]}, Special: {counts[3]}"
            )

            # Initialize deterministic stream
            stream = DeterministicStream(dk)

            # Enforce minimum counts
            self._enforce_minimum_counts(
                password_chars, stream, uppercase, lowercase, digits, special, counts
            )

            # Add additional symbols
            self._add_additional_symbols(password_chars, stream, special)

            # Balance distribution
            self._balance_distribution(
                password_chars, stream, uppercase, lowercase, digits, special
            )

            # Shuffle again to distribute the characters more evenly.  The key is
            # tweaked with the current ``stream.current_index`` so that each call produces a
            # unique but deterministic ordering.
            shuffle_key = hmac.new(
                dk, stream.current_index.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            password_chars = self._fisher_yates_hmac(password_chars, shuffle_key)
            logger.debug(
                "Shuffled password characters for balanced distribution using HMAC-Fisher-Yates."
            )

            # Final counts after modifications
            final_counts = self._count_char_types(
                password_chars, uppercase, lowercase, digits, special
            )
            logger.debug(
                f"Final character counts - Upper: {final_counts[0]}, Lower: {final_counts[1]}, Digits: {final_counts[2]}, Special: {final_counts[3]}"
            )

            return "".join(password_chars)

        except Exception as e:
            logger.error(f"Error ensuring password complexity: {e}", exc_info=True)
            print(colored(f"Error: Failed to ensure password complexity: {e}", "red"))
            raise


def derive_ssh_key(bip85: BIP85, idx: int) -> bytes:
    """Derive 32 bytes of entropy suitable for an SSH key."""
    return bip85.derive_entropy(index=idx, entropy_bytes=32, app_no=32)


def derive_ssh_key_pair(parent_seed: str, index: int) -> tuple[str, str]:
    """Derive an Ed25519 SSH key pair from the seed phrase and index."""

    seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
    bip85 = BIP85(seed_bytes)
    entropy = derive_ssh_key(bip85, index)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(entropy)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return priv_pem, pub_pem


def derive_seed_phrase(bip85: BIP85, idx: int, words: int = 24) -> str:
    """Derive a new BIP39 seed phrase using BIP85."""
    return bip85.derive_mnemonic(index=idx, words_num=words)


def derive_pgp_key(
    bip85: BIP85, idx: int, key_type: str = "ed25519", user_id: str = ""
) -> tuple[str, str, str]:
    """Derive deterministic armored PGP material.

    Returns ``(private_key, public_key, fingerprint)``.

    For RSA keys the randomness required during key generation is provided by
    an HMAC-SHA256 based deterministic generator seeded from the BIP-85
    entropy. This avoids use of Python's ``random`` module while ensuring the
    output remains stable across Python versions.
    """

    from pgpy import PGPKey, PGPUID
    from pgpy.packet.packets import PrivKeyV4
    from pgpy.packet.fields import (
        EdDSAPriv,
        RSAPriv,
        ECPoint,
        ECPointFormat,
        EllipticCurveOID,
        MPI,
    )
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import inverse
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import hashlib
    import datetime

    entropy = bip85.derive_entropy(index=idx, entropy_bytes=32, app_no=32)
    created = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)

    if key_type.lower() == "rsa":

        class DRNG:
            """HMAC-SHA256 based deterministic random generator."""

            def __init__(self, seed: bytes) -> None:
                self.key = seed
                self.counter = 0

            def __call__(self, n: int) -> bytes:  # pragma: no cover - deterministic
                out = b""
                while len(out) < n:
                    msg = self.counter.to_bytes(4, "big")
                    out += hmac.new(self.key, msg, hashlib.sha256).digest()
                    self.counter += 1
                return out[:n]

        rsa_key = RSA.generate(2048, randfunc=DRNG(entropy))
        keymat = RSAPriv()
        keymat.n = MPI(rsa_key.n)
        keymat.e = MPI(rsa_key.e)
        keymat.d = MPI(rsa_key.d)
        keymat.p = MPI(rsa_key.p)
        keymat.q = MPI(rsa_key.q)
        keymat.u = MPI(inverse(keymat.p, keymat.q))
        keymat._compute_chksum()

        pkt = PrivKeyV4()
        pkt.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        pkt.keymaterial = keymat
    else:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(entropy)
        public = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        keymat = EdDSAPriv()
        keymat.oid = EllipticCurveOID.Ed25519
        keymat.s = MPI(int.from_bytes(entropy, "big"))
        keymat.p = ECPoint.from_values(
            keymat.oid.key_size, ECPointFormat.Native, public
        )
        keymat._compute_chksum()

        pkt = PrivKeyV4()
        pkt.pkalg = PubKeyAlgorithm.EdDSA
        pkt.keymaterial = keymat

    pkt.created = created
    pkt.update_hlen()
    key = PGPKey()
    key._key = pkt
    uid = PGPUID.new(user_id)
    key.add_uid(
        uid,
        usage=[
            KeyFlags.Sign,
            KeyFlags.EncryptCommunications,
            KeyFlags.EncryptStorage,
        ],
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        created=created,
    )
    return str(key), str(key.pubkey), key.fingerprint
