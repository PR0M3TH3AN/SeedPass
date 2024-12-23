# password_manager/password_generation.py

"""
Password Generation Module

This module provides the PasswordGenerator class responsible for deterministic password generation
based on a BIP-39 parent seed. It leverages BIP-85 for entropy derivation and ensures that
generated passwords meet complexity requirements.

Ensure that all dependencies are installed and properly configured in your environment.

Never ever ever use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed.
This means it should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this software's use case.
"""

import os
import logging
import hashlib
import string
import random
import traceback
from typing import Optional
from termcolor import colored
from pathlib import Path
import shutil
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from local_bip85.bip85 import BIP85

from constants import DEFAULT_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from password_manager.encryption import EncryptionManager

# Instantiate the logger
logger = logging.getLogger(__name__)

class PasswordGenerator:
    """
    PasswordGenerator Class

    Responsible for deterministic password generation based on a BIP-39 parent seed.
    Utilizes BIP-85 for entropy derivation and ensures that generated passwords meet
    complexity requirements.
    """

    def __init__(self, encryption_manager: EncryptionManager, parent_seed: str, bip85: BIP85):
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

            # Derive seed bytes from parent_seed using BIP39 (handled by EncryptionManager)
            self.seed_bytes = self.encryption_manager.derive_seed_from_mnemonic(self.parent_seed)

            logger.debug("PasswordGenerator initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize PasswordGenerator: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to initialize PasswordGenerator: {e}", 'red'))
            raise

    def generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH, index: int = 0) -> str:
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
                logger.error(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters.")
                raise ValueError(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters.")
            if length > MAX_PASSWORD_LENGTH:
                logger.error(f"Password length must not exceed {MAX_PASSWORD_LENGTH} characters.")
                raise ValueError(f"Password length must not exceed {MAX_PASSWORD_LENGTH} characters.")

            # Derive entropy using BIP-85
            entropy = self.bip85.derive_entropy(index=index, bytes_len=64, app_no=32)
            logger.debug(f"Derived entropy: {entropy.hex()}")

            # Use HKDF to derive key from entropy
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=None,
                info=b'password-generation',
                backend=default_backend()
            )
            derived_key = hkdf.derive(entropy)
            logger.debug(f"Derived key using HKDF: {derived_key.hex()}")

            # Use PBKDF2-HMAC-SHA256 to derive a key from entropy
            dk = hashlib.pbkdf2_hmac('sha256', entropy, b'', 100000)
            logger.debug(f"Derived key using PBKDF2: {dk.hex()}")

            # Map the derived key to all allowed characters
            all_allowed = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(all_allowed[byte % len(all_allowed)] for byte in dk)
            logger.debug(f"Password after mapping to all allowed characters: {password}")

            # Ensure the password meets complexity requirements
            password = self.ensure_complexity(password, all_allowed, dk)
            logger.debug(f"Password after ensuring complexity: {password}")

            # Shuffle characters deterministically based on dk
            shuffle_seed = int.from_bytes(dk, 'big')
            rng = random.Random(shuffle_seed)
            password_chars = list(password)
            rng.shuffle(password_chars)
            password = ''.join(password_chars)
            logger.debug("Shuffled password deterministically.")

            # Ensure password length by extending if necessary
            if len(password) < length:
                while len(password) < length:
                    dk = hashlib.pbkdf2_hmac('sha256', dk, b'', 1)
                    base64_extra = ''.join(all_allowed[byte % len(all_allowed)] for byte in dk)
                    password += ''.join(base64_extra)
                    logger.debug(f"Extended password: {password}")

            # Trim the password to the desired length
            password = password[:length]
            logger.debug(f"Final password (trimmed to {length} chars): {password}")

            return password

        except Exception as e:
            logger.error(f"Error generating password: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to generate password: {e}", 'red'))
            raise

    def ensure_complexity(self, password: str, alphabet: str, dk: bytes) -> str:
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
            special = string.punctuation

            password_chars = list(password)

            # Current counts
            current_upper = sum(1 for c in password_chars if c in uppercase)
            current_lower = sum(1 for c in password_chars if c in lowercase)
            current_digits = sum(1 for c in password_chars if c in digits)
            current_special = sum(1 for c in password_chars if c in special)

            logger.debug(f"Current character counts - Upper: {current_upper}, Lower: {current_lower}, Digits: {current_digits}, Special: {current_special}")

            # Set minimum counts
            min_upper = 2
            min_lower = 2
            min_digits = 2
            min_special = 2

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
                    logger.debug(f"Added uppercase letter '{char}' at position {index}.")

            if current_lower < min_lower:
                for _ in range(min_lower - current_lower):
                    index = get_dk_value() % len(password_chars)
                    char = lowercase[get_dk_value() % len(lowercase)]
                    password_chars[index] = char
                    logger.debug(f"Added lowercase letter '{char}' at position {index}.")

            if current_digits < min_digits:
                for _ in range(min_digits - current_digits):
                    index = get_dk_value() % len(password_chars)
                    char = digits[get_dk_value() % len(digits)]
                    password_chars[index] = char
                    logger.debug(f"Added digit '{char}' at position {index}.")

            if current_special < min_special:
                for _ in range(min_special - current_special):
                    index = get_dk_value() % len(password_chars)
                    char = special[get_dk_value() % len(special)]
                    password_chars[index] = char
                    logger.debug(f"Added special character '{char}' at position {index}.")

            # Additional deterministic inclusion of symbols to increase score
            symbol_target = 3  # Increase target number of symbols
            current_symbols = sum(1 for c in password_chars if c in special)
            additional_symbols_needed = max(symbol_target - current_symbols, 0)

            for _ in range(additional_symbols_needed):
                if dk_index >= dk_length:
                    break  # Avoid exceeding the derived key length
                index = get_dk_value() % len(password_chars)
                char = special[get_dk_value() % len(special)]
                password_chars[index] = char
                logger.debug(f"Added additional symbol '{char}' at position {index}.")

            # Ensure balanced distribution by assigning different character types to specific segments
            # Example: Divide password into segments and assign different types
            segment_length = len(password_chars) // 4
            if segment_length > 0:
                for i, char_type in enumerate([uppercase, lowercase, digits, special]):
                    segment_start = i * segment_length
                    segment_end = segment_start + segment_length
                    if segment_end > len(password_chars):
                        segment_end = len(password_chars)
                    for j in range(segment_start, segment_end):
                        if i == 0 and password_chars[j] not in uppercase:
                            char = uppercase[get_dk_value() % len(uppercase)]
                            password_chars[j] = char
                            logger.debug(f"Assigned uppercase letter '{char}' to position {j}.")
                        elif i == 1 and password_chars[j] not in lowercase:
                            char = lowercase[get_dk_value() % len(lowercase)]
                            password_chars[j] = char
                            logger.debug(f"Assigned lowercase letter '{char}' to position {j}.")
                        elif i == 2 and password_chars[j] not in digits:
                            char = digits[get_dk_value() % len(digits)]
                            password_chars[j] = char
                            logger.debug(f"Assigned digit '{char}' to position {j}.")
                        elif i == 3 and password_chars[j] not in special:
                            char = special[get_dk_value() % len(special)]
                            password_chars[j] = char
                            logger.debug(f"Assigned special character '{char}' to position {j}.")

            # Shuffle again to distribute the characters more evenly
            shuffle_seed = int.from_bytes(dk, 'big') + dk_index  # Modify seed to vary shuffle
            rng = random.Random(shuffle_seed)
            rng.shuffle(password_chars)
            logger.debug(f"Shuffled password characters for balanced distribution.")

            # Final counts after modifications
            final_upper = sum(1 for c in password_chars if c in uppercase)
            final_lower = sum(1 for c in password_chars if c in lowercase)
            final_digits = sum(1 for c in password_chars if c in digits)
            final_special = sum(1 for c in password_chars if c in special)
            logger.debug(f"Final character counts - Upper: {final_upper}, Lower: {final_lower}, Digits: {final_digits}, Special: {final_special}")

            return ''.join(password_chars)

        except Exception as e:
            logger.error(f"Error ensuring password complexity: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to ensure password complexity: {e}", 'red'))
            raise
