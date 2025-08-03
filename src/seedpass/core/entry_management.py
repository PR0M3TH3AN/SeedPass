# seedpass.core/entry_management.py

"""
Entry Management Module

This module implements the EntryManager class, responsible for handling
operations related to managing password entries in the deterministic password manager.
It provides methods to add, retrieve, modify, and list password entries, ensuring
that all changes are securely encrypted and properly indexed.

Ensure that all dependencies are installed and properly configured in your environment.

Never use or suggest using Random Salt. The purpose of this password manager is to derive
completely deterministic passwords from a BIP-85 seed, ensuring that passwords are generated
the same way every time. Salts would break this functionality and are not suitable for this software.
"""

try:
    import orjson as json_lib  # type: ignore

    USE_ORJSON = True
except Exception:  # pragma: no cover - fallback when orjson is missing
    import json as json_lib

    USE_ORJSON = False
import logging
import hashlib
import sys
import shutil
import time
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path

from termcolor import colored
from .migrations import LATEST_VERSION
from .entry_types import EntryType
from .totp import TotpManager
from utils.fingerprint import generate_fingerprint
from utils.checksum import canonical_json_dumps
from utils.atomic_write import atomic_write
from utils.key_validation import (
    validate_totp_secret,
    validate_ssh_key_pair,
    validate_pgp_private_key,
    validate_nostr_keys,
    validate_seed_phrase,
)

from .vault import Vault
from .backup import BackupManager


# Instantiate the logger
logger = logging.getLogger(__name__)


class EntryManager:
    def __init__(self, vault: Vault, backup_manager: BackupManager):
        """Initialize the EntryManager.

        Parameters:
            vault: The Vault instance for file access.
            backup_manager: Manages creation of entry database backups.
        """
        self.vault = vault
        self.backup_manager = backup_manager
        self.fingerprint_dir = backup_manager.fingerprint_dir

        # Use paths relative to the fingerprint directory
        self.index_file = self.fingerprint_dir / "seedpass_entries_db.json.enc"
        self.checksum_file = self.fingerprint_dir / "seedpass_entries_db_checksum.txt"

        self._index_cache: dict | None = None

        logger.debug(f"EntryManager initialized with index file at {self.index_file}")

    def clear_cache(self) -> None:
        """Clear the cached index data."""
        self._index_cache = None

    def _load_index(self, force_reload: bool = False) -> Dict[str, Any]:
        if not force_reload and self._index_cache is not None:
            return self._index_cache

        if self.index_file.exists():
            try:
                data = self.vault.load_index()
                # Normalize legacy fields
                for entry in data.get("entries", {}).values():
                    if "type" not in entry and "kind" in entry:
                        entry["type"] = entry["kind"]
                    if "kind" not in entry:
                        entry["kind"] = entry.get("type", EntryType.PASSWORD.value)
                    entry.setdefault("type", entry["kind"])
                    if "label" not in entry and "website" in entry:
                        entry["label"] = entry["website"]
                    if (
                        "website" in entry
                        and entry.get("type") == EntryType.PASSWORD.value
                    ):
                        entry.pop("website", None)
                    if "archived" not in entry and "blacklisted" in entry:
                        entry["archived"] = entry["blacklisted"]
                    entry.pop("blacklisted", None)
                    if "word_count" not in entry and "words" in entry:
                        entry["word_count"] = entry["words"]
                        entry.pop("words", None)
                    entry.setdefault("tags", [])
                    entry.setdefault("modified_ts", entry.get("updated", 0))
                logger.debug("Index loaded successfully.")
                self._index_cache = data
                return data
            except Exception as e:
                logger.error(f"Failed to load index: {e}")
                return {"schema_version": LATEST_VERSION, "entries": {}}
        else:
            logger.info(
                f"Index file '{self.index_file}' not found. Initializing new entries database."
            )
            data = {"schema_version": LATEST_VERSION, "entries": {}}
            self._index_cache = data
            return data

    def _save_index(self, data: Dict[str, Any]) -> None:
        try:
            self.vault.save_index(data)
            self._index_cache = data
            logger.debug("Index saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            raise

    def get_next_index(self) -> int:
        """
        Retrieves the next available index for a new entry.

        :return: The next index number as an integer.
        """
        try:
            data = self._load_index()
            if "entries" in data and isinstance(data["entries"], dict):
                indices = [int(idx) for idx in data["entries"].keys()]
                next_index = max(indices) + 1 if indices else 0
            else:
                next_index = 0
            logger.debug(f"Next index determined: {next_index}")
            return next_index
        except Exception as e:
            logger.error(f"Error determining next index: {e}", exc_info=True)
            print(colored(f"Error determining next index: {e}", "red"))
            sys.exit(1)

    def add_entry(
        self,
        label: str,
        length: int,
        username: Optional[str] = None,
        url: Optional[str] = None,
        archived: bool = False,
        notes: str = "",
        custom_fields: List[Dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        *,
        include_special_chars: bool | None = None,
        allowed_special_chars: str | None = None,
        special_mode: str | None = None,
        exclude_ambiguous: bool | None = None,
        min_uppercase: int | None = None,
        min_lowercase: int | None = None,
        min_digits: int | None = None,
        min_special: int | None = None,
    ) -> int:
        """
        Adds a new entry to the encrypted JSON index file.

        :param label: A label describing the entry (e.g. website name).
        :param length: The desired length of the password.
        :param username: (Optional) The username associated with the website.
        :param url: (Optional) The URL of the website.
        :param archived: (Optional) Whether the entry is archived. Defaults to False.
        :param notes: (Optional) Extra notes to attach to the entry.
        :return: The assigned index of the new entry.
        """
        try:
            index = self.get_next_index()
            data = self._load_index()

            data.setdefault("entries", {})
            entry = {
                "label": label,
                "length": length,
                "username": username if username else "",
                "url": url if url else "",
                "archived": archived,
                "type": EntryType.PASSWORD.value,
                "kind": EntryType.PASSWORD.value,
                "notes": notes,
                "modified_ts": int(time.time()),
                "custom_fields": custom_fields or [],
                "tags": tags or [],
            }

            policy: dict[str, Any] = {}
            if include_special_chars is not None:
                policy["include_special_chars"] = include_special_chars
            if allowed_special_chars is not None:
                policy["allowed_special_chars"] = allowed_special_chars
            if special_mode is not None:
                policy["special_mode"] = special_mode
            if exclude_ambiguous is not None:
                policy["exclude_ambiguous"] = exclude_ambiguous
            if min_uppercase is not None:
                policy["min_uppercase"] = int(min_uppercase)
            if min_lowercase is not None:
                policy["min_lowercase"] = int(min_lowercase)
            if min_digits is not None:
                policy["min_digits"] = int(min_digits)
            if min_special is not None:
                policy["min_special"] = int(min_special)
            if policy:
                entry["policy"] = policy

            data["entries"][str(index)] = entry

            logger.debug(
                f"Added entry at index {index} with label '{entry.get('label', '')}'."
            )

            self._save_index(data)
            self.update_checksum()
            self.backup_manager.create_backup()

            logger.info(f"Entry added successfully at index {index}.")
            print(colored(f"[+] Entry added successfully at index {index}.", "green"))

            return index  # Return the assigned index

        except Exception as e:
            logger.error(f"Failed to add entry: {e}", exc_info=True)
            print(colored(f"Error: Failed to add entry: {e}", "red"))
            sys.exit(1)

    def get_next_totp_index(self) -> int:
        """Return the next available derivation index for TOTP secrets."""
        data = self._load_index()
        entries = data.get("entries", {})
        indices = [
            int(v.get("index", 0))
            for v in entries.values()
            if (
                v.get("type") == EntryType.TOTP.value
                or v.get("kind") == EntryType.TOTP.value
            )
        ]
        return (max(indices) + 1) if indices else 0

    def add_totp(
        self,
        label: str,
        parent_seed: str,
        *,
        archived: bool = False,
        secret: str | None = None,
        index: int | None = None,
        period: int = 30,
        digits: int = 6,
        notes: str = "",
        tags: list[str] | None = None,
    ) -> str:
        """Add a new TOTP entry and return the provisioning URI."""
        entry_id = self.get_next_index()
        data = self._load_index()
        data.setdefault("entries", {})

        if secret is None:
            if index is None:
                index = self.get_next_totp_index()
            secret = TotpManager.derive_secret(parent_seed, index)
            if not validate_totp_secret(secret):
                raise ValueError("Invalid derived TOTP secret")
            entry = {
                "type": EntryType.TOTP.value,
                "kind": EntryType.TOTP.value,
                "label": label,
                "modified_ts": int(time.time()),
                "index": index,
                "period": period,
                "digits": digits,
                "archived": archived,
                "notes": notes,
                "tags": tags or [],
            }
        else:
            if not validate_totp_secret(secret):
                raise ValueError("Invalid TOTP secret")
            entry = {
                "type": EntryType.TOTP.value,
                "kind": EntryType.TOTP.value,
                "label": label,
                "secret": secret,
                "modified_ts": int(time.time()),
                "period": period,
                "digits": digits,
                "archived": archived,
                "notes": notes,
                "tags": tags or [],
            }

        data["entries"][str(entry_id)] = entry

        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()

        try:
            return TotpManager.make_otpauth_uri(label, secret, period, digits)
        except Exception as e:
            logger.error(f"Failed to generate otpauth URI: {e}")
            raise

    def add_ssh_key(
        self,
        label: str,
        parent_seed: str,
        index: int | None = None,
        notes: str = "",
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new SSH key pair entry.

        The provided ``index`` serves both as the vault entry identifier and
        derivation index for the key. If not supplied, the next available index
        is used. Only metadata is stored – keys are derived on demand.
        """

        if index is None:
            index = self.get_next_index()

        from .password_generation import derive_ssh_key_pair

        priv_pem, pub_pem = derive_ssh_key_pair(parent_seed, index)
        if not validate_ssh_key_pair(priv_pem, pub_pem):
            raise ValueError("Derived SSH key pair failed validation")

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.SSH.value,
            "kind": EntryType.SSH.value,
            "index": index,
            "label": label,
            "modified_ts": int(time.time()),
            "notes": notes,
            "archived": archived,
            "tags": tags or [],
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_ssh_key_pair(self, index: int, parent_seed: str) -> tuple[str, str]:
        """Return the PEM formatted SSH key pair for the given entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (etype != EntryType.SSH.value and kind != EntryType.SSH.value):
            raise ValueError("Entry is not an SSH key entry")

        from .password_generation import derive_ssh_key_pair

        key_index = int(entry.get("index", index))
        return derive_ssh_key_pair(parent_seed, key_index)

    def add_pgp_key(
        self,
        label: str,
        parent_seed: str,
        index: int | None = None,
        key_type: str = "ed25519",
        user_id: str = "",
        notes: str = "",
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new PGP key entry."""

        if index is None:
            index = self.get_next_index()

        from .password_generation import derive_pgp_key
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        priv_key, fp = derive_pgp_key(bip85, index, key_type, user_id)
        if not validate_pgp_private_key(priv_key, fp):
            raise ValueError("Derived PGP key failed validation")

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.PGP.value,
            "kind": EntryType.PGP.value,
            "index": index,
            "label": label,
            "modified_ts": int(time.time()),
            "key_type": key_type,
            "user_id": user_id,
            "notes": notes,
            "archived": archived,
            "tags": tags or [],
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_pgp_key(self, index: int, parent_seed: str) -> tuple[str, str]:
        """Return the armored PGP private key and fingerprint for the entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (etype != EntryType.PGP.value and kind != EntryType.PGP.value):
            raise ValueError("Entry is not a PGP key entry")

        from .password_generation import derive_pgp_key
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        key_idx = int(entry.get("index", index))
        key_type = entry.get("key_type", "ed25519")
        user_id = entry.get("user_id", "")
        return derive_pgp_key(bip85, key_idx, key_type, user_id)

    def add_nostr_key(
        self,
        label: str,
        parent_seed: str,
        index: int | None = None,
        notes: str = "",
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new Nostr key pair entry."""

        if index is None:
            index = self.get_next_index()

        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator
        from nostr.coincurve_keys import Keys

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)
        entropy = bip85.derive_entropy(index=index, bytes_len=32)
        keys = Keys(priv_k=entropy.hex())
        npub = Keys.hex_to_bech32(keys.public_key_hex(), "npub")
        nsec = Keys.hex_to_bech32(keys.private_key_hex(), "nsec")
        if not validate_nostr_keys(npub, nsec):
            raise ValueError("Derived Nostr keys failed validation")

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.NOSTR.value,
            "kind": EntryType.NOSTR.value,
            "index": index,
            "label": label,
            "modified_ts": int(time.time()),
            "notes": notes,
            "archived": archived,
            "tags": tags or [],
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def add_key_value(
        self,
        label: str,
        key: str,
        value: str,
        *,
        notes: str = "",
        custom_fields=None,
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new generic key/value entry."""

        index = self.get_next_index()

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.KEY_VALUE.value,
            "kind": EntryType.KEY_VALUE.value,
            "label": label,
            "key": key,
            "modified_ts": int(time.time()),
            "value": value,
            "notes": notes,
            "archived": archived,
            "custom_fields": custom_fields or [],
            "tags": tags or [],
        }

        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_nostr_key_pair(self, index: int, parent_seed: str) -> tuple[str, str]:
        """Return the npub and nsec for the specified entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type", "").lower() if entry else ""
        kind = entry.get("kind", "").lower() if entry else ""
        if not entry or (
            etype != EntryType.NOSTR.value and kind != EntryType.NOSTR.value
        ):
            raise ValueError("Entry is not a Nostr key entry")

        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator
        from nostr.coincurve_keys import Keys

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        key_idx = int(entry.get("index", index))
        entropy = bip85.derive_entropy(index=key_idx, bytes_len=32)
        keys = Keys(priv_k=entropy.hex())
        npub = Keys.hex_to_bech32(keys.public_key_hex(), "npub")
        nsec = Keys.hex_to_bech32(keys.private_key_hex(), "nsec")
        return npub, nsec

    def add_seed(
        self,
        label: str,
        parent_seed: str,
        index: int | None = None,
        words_num: int = 24,
        notes: str = "",
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new derived seed phrase entry."""

        if index is None:
            index = self.get_next_index()

        from .password_generation import derive_seed_phrase
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)
        phrase = derive_seed_phrase(bip85, index, words_num)
        if not validate_seed_phrase(phrase):
            raise ValueError("Derived seed phrase failed validation")

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.SEED.value,
            "kind": EntryType.SEED.value,
            "index": index,
            "label": label,
            "modified_ts": int(time.time()),
            "word_count": words_num,
            "notes": notes,
            "archived": archived,
            "tags": tags or [],
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_seed_phrase(self, index: int, parent_seed: str) -> str:
        """Return the mnemonic seed phrase for the given entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.SEED.value and kind != EntryType.SEED.value
        ):
            raise ValueError("Entry is not a seed entry")

        from .password_generation import derive_seed_phrase
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        words = int(entry.get("word_count", entry.get("words", 24)))
        seed_index = int(entry.get("index", index))
        return derive_seed_phrase(bip85, seed_index, words)

    def add_managed_account(
        self,
        label: str,
        parent_seed: str,
        *,
        index: int | None = None,
        notes: str = "",
        archived: bool = False,
        tags: list[str] | None = None,
    ) -> int:
        """Add a new managed account seed entry.

        Managed accounts always use a 12-word seed phrase.
        """

        if index is None:
            index = self.get_next_index()

        from .password_generation import derive_seed_phrase
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        word_count = 12

        seed_phrase = derive_seed_phrase(bip85, index, word_count)
        if not validate_seed_phrase(seed_phrase):
            raise ValueError("Derived managed account seed failed validation")
        fingerprint = generate_fingerprint(seed_phrase)

        account_dir = self.fingerprint_dir / "accounts" / fingerprint
        account_dir.mkdir(parents=True, exist_ok=True)

        data = self._load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.MANAGED_ACCOUNT.value,
            "kind": EntryType.MANAGED_ACCOUNT.value,
            "index": index,
            "label": label,
            "modified_ts": int(time.time()),
            "word_count": word_count,
            "notes": notes,
            "fingerprint": fingerprint,
            "archived": archived,
            "tags": tags or [],
        }

        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_managed_account_seed(self, index: int, parent_seed: str) -> str:
        """Return the seed phrase for a managed account entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.MANAGED_ACCOUNT.value
            and kind != EntryType.MANAGED_ACCOUNT.value
        ):
            raise ValueError("Entry is not a managed account entry")

        from .password_generation import derive_seed_phrase
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        words = int(entry.get("word_count", 12))
        seed_index = int(entry.get("index", index))
        return derive_seed_phrase(bip85, seed_index, words)

    def get_totp_code(
        self, index: int, parent_seed: str | None = None, timestamp: int | None = None
    ) -> str:
        """Return the current TOTP code for the specified entry."""
        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.TOTP.value and kind != EntryType.TOTP.value
        ):
            raise ValueError("Entry is not a TOTP entry")
        if "secret" in entry:
            return TotpManager.current_code_from_secret(entry["secret"], timestamp)
        if parent_seed is None:
            raise ValueError("Seed required for derived TOTP")
        totp_index = int(entry.get("index", 0))
        return TotpManager.current_code(parent_seed, totp_index, timestamp)

    def get_totp_time_remaining(self, index: int) -> int:
        """Return seconds remaining in the TOTP period for the given entry."""
        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.TOTP.value and kind != EntryType.TOTP.value
        ):
            raise ValueError("Entry is not a TOTP entry")

        period = int(entry.get("period", 30))
        return TotpManager.time_remaining(period)

    def export_totp_entries(self, parent_seed: str) -> dict[str, list[dict[str, Any]]]:
        """Return all TOTP secrets and metadata for external use."""
        data = self._load_index()
        entries = data.get("entries", {})
        exported: list[dict[str, Any]] = []
        for entry in entries.values():
            etype = entry.get("type", entry.get("kind"))
            if etype != EntryType.TOTP.value:
                continue
            label = entry.get("label", "")
            period = int(entry.get("period", 30))
            digits = int(entry.get("digits", 6))
            if "secret" in entry:
                secret = entry["secret"]
            else:
                idx = int(entry.get("index", 0))
                secret = TotpManager.derive_secret(parent_seed, idx)
            uri = TotpManager.make_otpauth_uri(label, secret, period, digits)
            exported.append(
                {
                    "label": label,
                    "secret": secret,
                    "period": period,
                    "digits": digits,
                    "uri": uri,
                }
            )
        return {"entries": exported}

    def get_encrypted_index(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index file's contents.

        :return: The encrypted data as bytes, or None if retrieval fails.
        """
        try:
            return self.vault.get_encrypted_index()
        except Exception as e:
            logger.error(f"Failed to retrieve encrypted index file: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to retrieve encrypted index file: {e}", "red")
            )
            return None

    def retrieve_entry(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves an entry based on the provided index.

        :param index: The index number of the entry.
        :return: A dictionary containing the entry details or None if not found.
        """
        try:
            data = self._load_index()
            entry = data.get("entries", {}).get(str(index))

            if entry:
                etype = entry.get("type", entry.get("kind"))
                if etype in (
                    EntryType.PASSWORD.value,
                    EntryType.KEY_VALUE.value,
                    EntryType.MANAGED_ACCOUNT.value,
                ):
                    entry.setdefault("custom_fields", [])
                logger.debug(
                    f"Retrieved entry at index {index} with label '{entry.get('label', '')}'."
                )
                clean = {k: v for k, v in entry.items() if k != "modified_ts"}
                return clean
            else:
                logger.warning(f"No entry found at index {index}.")
                print(colored(f"Warning: No entry found at index {index}.", "yellow"))
                return None

        except Exception as e:
            logger.error(
                f"Failed to retrieve entry at index {index}: {e}", exc_info=True
            )
            print(
                colored(f"Error: Failed to retrieve entry at index {index}: {e}", "red")
            )
            return None

    def modify_entry(
        self,
        index: int,
        username: Optional[str] = None,
        url: Optional[str] = None,
        archived: Optional[bool] = None,
        notes: Optional[str] = None,
        *,
        label: Optional[str] = None,
        period: Optional[int] = None,
        digits: Optional[int] = None,
        key: Optional[str] = None,
        value: Optional[str] = None,
        custom_fields: List[Dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        include_special_chars: bool | None = None,
        allowed_special_chars: str | None = None,
        special_mode: str | None = None,
        exclude_ambiguous: bool | None = None,
        min_uppercase: int | None = None,
        min_lowercase: int | None = None,
        min_digits: int | None = None,
        min_special: int | None = None,
        **legacy,
    ) -> None:
        """
        Modifies an existing entry based on the provided index and new values.

        :param index: The index number of the entry to modify.
        :param username: (Optional) The new username (password entries).
        :param url: (Optional) The new URL (password entries).
        :param archived: (Optional) The new archived status.
        :param notes: (Optional) New notes to attach to the entry.
        :param label: (Optional) The new label for the entry.
        :param period: (Optional) The new TOTP period in seconds.
        :param digits: (Optional) The new number of digits for TOTP codes.
        :param key: (Optional) New key for key/value entries.
        :param value: (Optional) New value for key/value entries.
        """
        try:
            data = self._load_index()
            entry = data.get("entries", {}).get(str(index))

            if not entry:
                logger.warning(
                    f"No entry found at index {index}. Cannot modify non-existent entry."
                )
                print(
                    colored(
                        f"Warning: No entry found at index {index}. Cannot modify non-existent entry.",
                        "yellow",
                    )
                )
                return

            entry_type = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))

            provided_fields = {
                "username": username,
                "url": url,
                "archived": archived,
                "notes": notes,
                "label": label,
                "period": period,
                "digits": digits,
                "key": key,
                "value": value,
                "custom_fields": custom_fields,
                "tags": tags,
                "include_special_chars": include_special_chars,
                "allowed_special_chars": allowed_special_chars,
                "special_mode": special_mode,
                "exclude_ambiguous": exclude_ambiguous,
                "min_uppercase": min_uppercase,
                "min_lowercase": min_lowercase,
                "min_digits": min_digits,
                "min_special": min_special,
            }

            allowed = {
                EntryType.PASSWORD.value: {
                    "username",
                    "url",
                    "label",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                    "include_special_chars",
                    "allowed_special_chars",
                    "special_mode",
                    "exclude_ambiguous",
                    "min_uppercase",
                    "min_lowercase",
                    "min_digits",
                    "min_special",
                },
                EntryType.TOTP.value: {
                    "label",
                    "period",
                    "digits",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.KEY_VALUE.value: {
                    "label",
                    "key",
                    "value",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.MANAGED_ACCOUNT.value: {
                    "label",
                    "value",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.SSH.value: {
                    "label",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.PGP.value: {
                    "label",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.NOSTR.value: {
                    "label",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
                EntryType.SEED.value: {
                    "label",
                    "archived",
                    "notes",
                    "custom_fields",
                    "tags",
                },
            }

            allowed_fields = allowed.get(entry_type, set())
            invalid = {
                k for k, v in provided_fields.items() if v is not None
            } - allowed_fields
            if invalid:
                raise ValueError(
                    f"Entry type '{entry_type}' does not support fields: {', '.join(sorted(invalid))}"
                )

            if entry_type == EntryType.TOTP.value:
                if label is not None:
                    entry["label"] = label
                    logger.debug(f"Updated label to '{label}' for index {index}.")
                if period is not None:
                    entry["period"] = period
                    logger.debug(f"Updated period to '{period}' for index {index}.")
                if digits is not None:
                    entry["digits"] = digits
                    logger.debug(f"Updated digits to '{digits}' for index {index}.")
            else:
                if label is not None:
                    entry["label"] = label
                    logger.debug(f"Updated label to '{label}' for index {index}.")
                if entry_type == EntryType.PASSWORD.value:
                    if username is not None:
                        entry["username"] = username
                        logger.debug(
                            f"Updated username to '{username}' for index {index}."
                        )
                    if url is not None:
                        entry["url"] = url
                        logger.debug(f"Updated URL to '{url}' for index {index}.")
                elif entry_type in (
                    EntryType.KEY_VALUE.value,
                    EntryType.MANAGED_ACCOUNT.value,
                ):
                    if key is not None and entry_type == EntryType.KEY_VALUE.value:
                        entry["key"] = key
                        logger.debug(f"Updated key for index {index}.")
                    if value is not None:
                        entry["value"] = value
                        logger.debug(f"Updated value for index {index}.")

            if archived is None and "blacklisted" in legacy:
                archived = legacy["blacklisted"]

            if archived is not None:
                entry["archived"] = archived
                if "blacklisted" in entry:
                    entry.pop("blacklisted", None)
                logger.debug(
                    f"Updated archived status to '{archived}' for index {index}."
                )

            if notes is not None:
                entry["notes"] = notes
                logger.debug(f"Updated notes for index {index}.")

            if custom_fields is not None:
                entry["custom_fields"] = custom_fields
                logger.debug(f"Updated custom fields for index {index}.")

            if tags is not None:
                entry["tags"] = tags
                logger.debug(f"Updated tags for index {index}.")

            policy_updates: dict[str, Any] = {}
            if include_special_chars is not None:
                policy_updates["include_special_chars"] = include_special_chars
            if allowed_special_chars is not None:
                policy_updates["allowed_special_chars"] = allowed_special_chars
            if special_mode is not None:
                policy_updates["special_mode"] = special_mode
            if exclude_ambiguous is not None:
                policy_updates["exclude_ambiguous"] = exclude_ambiguous
            if min_uppercase is not None:
                policy_updates["min_uppercase"] = int(min_uppercase)
            if min_lowercase is not None:
                policy_updates["min_lowercase"] = int(min_lowercase)
            if min_digits is not None:
                policy_updates["min_digits"] = int(min_digits)
            if min_special is not None:
                policy_updates["min_special"] = int(min_special)
            if policy_updates:
                entry_policy = entry.get("policy", {})
                entry_policy.update(policy_updates)
                entry["policy"] = entry_policy

            entry["modified_ts"] = int(time.time())

            data["entries"][str(index)] = entry
            logger.debug(
                f"Modified entry at index {index} with label '{entry.get('label', '')}'."
            )

            self._save_index(data)
            self.update_checksum()
            self.backup_manager.create_backup()

            logger.info(f"Entry at index {index} modified successfully.")
            print(
                colored(f"[+] Entry at index {index} modified successfully.", "green")
            )

        except Exception as e:
            logger.error(f"Failed to modify entry at index {index}: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to modify entry at index {index}: {e}", "red")
            )
            raise

    def archive_entry(self, index: int) -> None:
        """Mark the specified entry as archived."""
        self.modify_entry(index, archived=True)

    def restore_entry(self, index: int) -> None:
        """Unarchive the specified entry."""
        self.modify_entry(index, archived=False)

    def list_entries(
        self,
        sort_by: str = "index",
        filter_kind: str | None = None,
        *,
        include_archived: bool = False,
        verbose: bool = True,
    ) -> List[Tuple[int, str, Optional[str], Optional[str], bool]]:
        """List entries sorted and filtered according to the provided options.

        Parameters
        ----------
        sort_by:
            Field to sort by. Supported values are ``"index"``, ``"label"`` and
            ``"updated"``.
        filter_kind:
            Optional entry kind to restrict the results.

        Archived entries are omitted unless ``include_archived`` is ``True``.
        """
        try:
            data = self._load_index()
            entries_data = data.get("entries", {})

            if not entries_data:
                logger.info("No entries found.")
                if verbose:
                    print(colored("No entries found.", "yellow"))
                return []

            def sort_key(item: Tuple[str, Dict[str, Any]]):
                idx_str, entry = item
                if sort_by == "index":
                    return int(idx_str)
                if sort_by == "label":
                    # labels are stored in the index so no additional
                    # decryption is required when sorting
                    return entry.get("label", entry.get("website", "")).lower()
                if sort_by == "updated":
                    # sort newest first
                    return -int(entry.get("updated", 0))
                raise ValueError("sort_by must be 'index', 'label', or 'updated'")

            sorted_items = sorted(entries_data.items(), key=sort_key)

            filtered_items: List[Tuple[int, Dict[str, Any]]] = []
            for idx_str, entry in sorted_items:
                if (
                    filter_kind is not None
                    and entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                    != filter_kind
                ):
                    continue
                if not include_archived and entry.get(
                    "archived", entry.get("blacklisted", False)
                ):
                    continue
                filtered_items.append((int(idx_str), entry))

            entries: List[Tuple[int, str, Optional[str], Optional[str], bool]] = []
            for idx, entry in filtered_items:
                label = entry.get("label", entry.get("website", ""))
                etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                if etype == EntryType.PASSWORD.value:
                    entries.append(
                        (
                            idx,
                            label,
                            entry.get("username", ""),
                            entry.get("url", ""),
                            entry.get("archived", entry.get("blacklisted", False)),
                        )
                    )
                else:
                    entries.append(
                        (
                            idx,
                            label,
                            None,
                            None,
                            entry.get("archived", entry.get("blacklisted", False)),
                        )
                    )

            logger.debug(f"Total entries found: {len(entries)}")
            if verbose:
                for idx, entry in filtered_items:
                    etype = entry.get(
                        "type", entry.get("kind", EntryType.PASSWORD.value)
                    )
                    print(colored(f"Index: {idx}", "cyan"))
                    if etype == EntryType.TOTP.value:
                        print(colored("  Type: TOTP", "cyan"))
                        print(colored(f"  Label: {entry.get('label', '')}", "cyan"))
                        print(
                            colored(f"  Derivation Index: {entry.get('index')}", "cyan")
                        )
                        print(
                            colored(
                                f"  Period: {entry.get('period', 30)}s  Digits: {entry.get('digits', 6)}",
                                "cyan",
                            )
                        )
                    elif etype == EntryType.PASSWORD.value:
                        print(
                            colored(
                                f"  Label: {entry.get('label', entry.get('website', ''))}",
                                "cyan",
                            )
                        )
                        print(
                            colored(
                                f"  Username: {entry.get('username') or 'N/A'}", "cyan"
                            )
                        )
                        print(colored(f"  URL: {entry.get('url') or 'N/A'}", "cyan"))
                        print(
                            colored(
                                f"  Archived: {'Yes' if entry.get('archived', entry.get('blacklisted', False)) else 'No'}",
                                "cyan",
                            )
                        )
                    else:
                        print(colored(f"  Label: {entry.get('label', '')}", "cyan"))
                        print(
                            colored(
                                f"  Derivation Index: {entry.get('index', idx)}",
                                "cyan",
                            )
                        )
                    print("-" * 40)

            return entries

        except Exception as e:
            logger.error(f"Failed to list entries: {e}", exc_info=True)
            if verbose:
                print(colored(f"Error: Failed to list entries: {e}", "red"))
            return []

    def search_entries(
        self, query: str, kinds: List[str] | None = None
    ) -> List[Tuple[int, str, Optional[str], Optional[str], bool, EntryType]]:
        """Return entries matching ``query`` across whitelisted metadata fields.

        Each match is represented as ``(index, label, username, url, archived, etype)``
        where ``etype`` is the :class:`EntryType` of the entry.
        """

        data = self._load_index()
        entries_data = data.get("entries", {})

        if not entries_data:
            return []

        query_lower = query.lower()
        results: List[
            Tuple[int, str, Optional[str], Optional[str], bool, EntryType]
        ] = []

        for idx, entry in sorted(entries_data.items(), key=lambda x: int(x[0])):
            etype = EntryType(
                entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
            )

            if kinds is not None and etype.value not in kinds:
                continue

            label = entry.get("label", entry.get("website", ""))
            username = (
                entry.get("username", "") if etype == EntryType.PASSWORD else None
            )
            url = entry.get("url", "") if etype == EntryType.PASSWORD else None
            tags = entry.get("tags", [])
            archived = entry.get("archived", entry.get("blacklisted", False))

            label_match = query_lower in label.lower()
            username_match = bool(username) and query_lower in username.lower()
            url_match = bool(url) and query_lower in url.lower()
            tags_match = any(query_lower in str(t).lower() for t in tags)

            if label_match or username_match or url_match or tags_match:
                results.append(
                    (
                        int(idx),
                        label,
                        username if username is not None else None,
                        url if url is not None else None,
                        archived,
                        etype,
                    )
                )

        return results

    def delete_entry(self, index: int) -> None:
        """
        Deletes an entry based on the provided index.

        :param index: The index number of the entry to delete.
        """
        try:
            data = self._load_index()
            if "entries" in data and str(index) in data["entries"]:
                del data["entries"][str(index)]
                logger.debug(f"Deleted entry at index {index}.")
                self._save_index(data)
                self.update_checksum()
                self.backup_manager.create_backup()
                logger.info(f"Entry at index {index} deleted successfully.")
                print(
                    colored(
                        f"[+] Entry at index {index} deleted successfully.", "green"
                    )
                )
            else:
                logger.warning(
                    f"No entry found at index {index}. Cannot delete non-existent entry."
                )
                print(
                    colored(
                        f"Warning: No entry found at index {index}. Cannot delete non-existent entry.",
                        "yellow",
                    )
                )

        except Exception as e:
            logger.error(f"Failed to delete entry at index {index}: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to delete entry at index {index}: {e}", "red")
            )

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database to ensure data integrity.
        """
        try:
            data = self._load_index()
            canonical = canonical_json_dumps(data)
            checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            # The checksum file path already includes the fingerprint directory
            checksum_path = self.checksum_file

            atomic_write(checksum_path, lambda f: f.write(checksum))

            logger.debug(f"Checksum updated and written to '{checksum_path}'.")
            print(colored(f"[+] Checksum updated successfully.", "green"))

        except Exception as e:
            logger.error(f"Failed to update checksum: {e}", exc_info=True)
            print(colored(f"Error: Failed to update checksum: {e}", "red"))

    def restore_from_backup(self, backup_path: str) -> None:
        """
        Restores the index file from a specified backup file.

        :param backup_path: The file path of the backup to restore from.
        """
        try:
            backup_path = Path(backup_path)
            if not backup_path.exists():
                logger.error(f"Backup file '{backup_path}' does not exist.")
                print(
                    colored(
                        f"Error: Backup file '{backup_path}' does not exist.", "red"
                    )
                )
                return

            with open(backup_path, "rb") as backup_file, open(
                self.index_file, "wb"
            ) as index_file:
                shutil.copyfileobj(backup_file, index_file)

            logger.debug(f"Index file restored from backup '{backup_path}'.")
            print(
                colored(
                    f"[+] Index file restored from backup '{backup_path}'.", "green"
                )
            )

            self.clear_cache()
            self.update_checksum()

        except Exception as e:
            logger.error(
                f"Failed to restore from backup '{backup_path}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to restore from backup '{backup_path}': {e}", "red"
                )
            )

    def list_all_entries(
        self,
        sort_by: str = "index",
        filter_kind: str | None = None,
        *,
        include_archived: bool = False,
    ) -> None:
        """Display all entries using :meth:`list_entries`."""
        try:
            entries = self.list_entries(
                sort_by=sort_by,
                filter_kind=filter_kind,
                include_archived=include_archived,
            )
            if not entries:
                print(colored("No entries to display.", "yellow"))
                return

            print(colored("\n[+] Listing All Entries:\n", "green"))
            for entry in entries:
                index, website, username, url, blacklisted = entry
                print(colored(f"Index: {index}", "cyan"))
                print(colored(f"  Label: {website}", "cyan"))
                print(colored(f"  Username: {username or 'N/A'}", "cyan"))
                print(colored(f"  URL: {url or 'N/A'}", "cyan"))
                print(colored(f"  Archived: {'Yes' if blacklisted else 'No'}", "cyan"))
                print("-" * 40)

        except Exception as e:
            logger.error(f"Failed to list all entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to list all entries: {e}", "red"))
            return

    def get_entry_summaries(
        self,
        filter_kind: str | None = None,
        *,
        include_archived: bool = False,
    ) -> list[tuple[int, str, str]]:
        """Return a list of entry index, type, and display labels."""
        try:
            data = self._load_index()
            entries_data = data.get("entries", {})

            summaries: list[tuple[int, str, str]] = []
            for idx_str, entry in entries_data.items():
                etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                if filter_kind and etype != filter_kind:
                    continue
                if not include_archived and entry.get(
                    "archived", entry.get("blacklisted", False)
                ):
                    continue
                if etype == EntryType.PASSWORD.value:
                    label = entry.get("label", entry.get("website", ""))
                else:
                    label = entry.get("label", etype)
                summaries.append((int(idx_str), etype, label))

            summaries.sort(key=lambda x: x[0])
            return summaries
        except Exception as e:
            logger.error(f"Failed to get entry summaries: {e}", exc_info=True)
            print(colored(f"Error: Failed to get entry summaries: {e}", "red"))
            return []
