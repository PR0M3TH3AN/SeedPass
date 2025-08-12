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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from bip_utils import Bip39SeedGenerator

# Ensure the ``imghdr`` module is available for ``pgpy`` on Python 3.13+
try:  # pragma: no cover - only executed on Python >= 3.13
    import imghdr  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for removed module
    from utils import imghdr_stub as imghdr  # type: ignore
    import sys

    sys.modules.setdefault("imghdr", imghdr)

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

            # Derive seed bytes from parent_seed using BIP39 (handled by EncryptionManager)
            self.seed_bytes = self.encryption_manager.derive_seed_from_mnemonic(
                self.parent_seed
            )

            logger.debug("PasswordGenerator initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize PasswordGenerator: {e}", exc_info=True)
            print(colored(f"Error: Failed to initialize PasswordGenerator: {e}", "red"))
            raise

    def _derive_password_entropy(self, index: int) -> bytes:
        """Derive deterministic entropy for password generation."""
        entropy = self.bip85.derive_entropy(index=index, entropy_bytes=64, app_no=32)
        logger.debug("Entropy derived for password generation.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"password-generation",
            backend=default_backend(),
        )
        hkdf_derived = hkdf.derive(entropy)
        logger.debug("Derived key using HKDF.")

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
        self, length: int = DEFAULT_PASSWORD_LENGTH, index: int = 0
    ) -> str:
        """
        Generates a deterministic password based on the parent seed, desired length, and index.

        Steps:
        1. Derive entropy using BIP-85.
        2. Use HKDF-HMAC-SHA256 to derive a key from entropy.
        3. Map the derived key to all allowed characters.
        4. Ensure the password meets complexity requirements.
        5. Shuffle the password deterministically based on the derived key.
        6. Trim or extend the password to the desired length.

        Parameters:
            length (int): Desired length of the password.
            index (int): Index for deriving child entropy.

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

            all_allowed = letters + digits + allowed_special
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

            # Current counts
            current_upper = sum(1 for c in password_chars if c in uppercase)
            current_lower = sum(1 for c in password_chars if c in lowercase)
            current_digits = sum(1 for c in password_chars if c in digits)
            current_special = sum(1 for c in password_chars if c in special)

            logger.debug(
                f"Current character counts - Upper: {current_upper}, Lower: {current_lower}, Digits: {current_digits}, Special: {current_special}"
            )

            # Set minimum counts from policy
            min_upper = self.policy.min_uppercase
            min_lower = self.policy.min_lowercase
            min_digits = self.policy.min_digits
            min_special = self.policy.min_special if special else 0

            # Initialize derived key index
            dk_index = 0
            dk_length = len(dk)

            def get_dk_value() -> int:
                nonlocal dk_index
                value = dk[dk_index % dk_length]
                dk_index += 1
                return value

            # Replace characters to meet minimum counts
            if current_upper < min_upper:
                for _ in range(min_upper - current_upper):
                    index = get_dk_value() % len(password_chars)
                    char = uppercase[get_dk_value() % len(uppercase)]
                    password_chars[index] = char
                    logger.debug(f"Added uppercase letter at position {index}.")

            if current_lower < min_lower:
                for _ in range(min_lower - current_lower):
                    index = get_dk_value() % len(password_chars)
                    char = lowercase[get_dk_value() % len(lowercase)]
                    password_chars[index] = char
                    logger.debug(f"Added lowercase letter at position {index}.")

            if current_digits < min_digits:
                for _ in range(min_digits - current_digits):
                    index = get_dk_value() % len(password_chars)
                    char = digits[get_dk_value() % len(digits)]
                    password_chars[index] = char
                    logger.debug(f"Added digit at position {index}.")

            if special and current_special < min_special:
                for _ in range(min_special - current_special):
                    index = get_dk_value() % len(password_chars)
                    char = special[get_dk_value() % len(special)]
                    password_chars[index] = char
                    logger.debug(f"Added special character at position {index}.")

            # Additional deterministic inclusion of symbols to increase score
            if special:
                symbol_target = 3  # Increase target number of symbols
                current_symbols = sum(1 for c in password_chars if c in special)
                additional_symbols_needed = max(symbol_target - current_symbols, 0)

                for _ in range(additional_symbols_needed):
                    if dk_index >= dk_length:
                        break  # Avoid exceeding the derived key length
                    index = get_dk_value() % len(password_chars)
                    char = special[get_dk_value() % len(special)]
                    password_chars[index] = char
                    logger.debug(f"Added additional symbol at position {index}.")

            # Ensure balanced distribution by assigning different character types to specific segments
            # Example: Divide password into segments and assign different types
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
                            char = uppercase[get_dk_value() % len(uppercase)]
                            password_chars[j] = char
                            logger.debug(f"Assigned uppercase letter to position {j}.")
                        elif i == 1 and password_chars[j] not in lowercase:
                            char = lowercase[get_dk_value() % len(lowercase)]
                            password_chars[j] = char
                            logger.debug(f"Assigned lowercase letter to position {j}.")
                        elif i == 2 and password_chars[j] not in digits:
                            char = digits[get_dk_value() % len(digits)]
                            password_chars[j] = char
                            logger.debug(f"Assigned digit to position {j}.")
                        elif (
                            special
                            and i == len(char_types) - 1
                            and password_chars[j] not in special
                        ):
                            char = special[get_dk_value() % len(special)]
                            password_chars[j] = char
                            logger.debug(f"Assigned special character to position {j}.")

            # Shuffle again to distribute the characters more evenly.  The key is
            # tweaked with the current ``dk_index`` so that each call produces a
            # unique but deterministic ordering.
            shuffle_key = hmac.new(
                dk, dk_index.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            password_chars = self._fisher_yates_hmac(password_chars, shuffle_key)
            logger.debug(
                "Shuffled password characters for balanced distribution using HMAC-Fisher-Yates."
            )

            # Final counts after modifications
            final_upper = sum(1 for c in password_chars if c in uppercase)
            final_lower = sum(1 for c in password_chars if c in lowercase)
            final_digits = sum(1 for c in password_chars if c in digits)
            final_special = sum(1 for c in password_chars if c in special)
            logger.debug(
                f"Final character counts - Upper: {final_upper}, Lower: {final_lower}, Digits: {final_digits}, Special: {final_special}"
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
) -> tuple[str, str]:
    """Derive a deterministic PGP private key and return it with its fingerprint.

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
    return str(key), key.fingerprint
