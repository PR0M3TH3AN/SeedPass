#!/usr/bin/env python3
"""Generate a SeedPass test profile with realistic entries.

This script populates a profile directory with a variety of entry types,
including key/value pairs and managed accounts.
If the profile does not exist, a new BIP-39 seed phrase is generated and
stored encrypted. A clear text copy is written to ``seed_phrase.txt`` so
it can be reused across devices.

Profiles are saved under ``~/.seedpass/tests/`` by default. SeedPass
only detects a profile automatically when it resides directly under
``~/.seedpass/``. Copy the generated fingerprint directory from the
``tests`` subfolder to ``~/.seedpass`` (or adjust ``APP_DIR`` in
``constants.py``) to use the test seed with the main application.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from bip_utils import Bip39Languages, Bip39MnemonicGenerator, Bip39WordsNum

# Ensure src directory is in sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import constants as consts

# Use a dedicated subdirectory for test profiles so regular data is not polluted
consts.APP_DIR = consts.APP_DIR / "tests"
consts.PARENT_SEED_FILE = consts.APP_DIR / "parent_seed.enc"
consts.SCRIPT_CHECKSUM_FILE = consts.APP_DIR / "seedpass_script_checksum.txt"

from constants import APP_DIR, initialize_app
from utils.key_derivation import derive_key_from_password, derive_index_key
from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager
from password_manager.backup import BackupManager
from password_manager.entry_management import EntryManager
from nostr.client import NostrClient
from utils.fingerprint import generate_fingerprint
from utils.fingerprint_manager import FingerprintManager
import bcrypt
import asyncio
import gzip

DEFAULT_PASSWORD = "testpassword"


def initialize_profile(
    profile_name: str,
) -> tuple[str, EntryManager, Path, str, ConfigManager]:
    """Create or load a profile and return the seed phrase, manager, directory and fingerprint."""
    initialize_app()
    seed_txt = APP_DIR / f"{profile_name}_seed.txt"
    if seed_txt.exists():
        seed_phrase = seed_txt.read_text().strip()
    else:
        seed_phrase = (
            Bip39MnemonicGenerator(Bip39Languages.ENGLISH)
            .FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
            .ToStr()
        )
        seed_txt.write_text(seed_phrase)
        seed_txt.chmod(0o600)

    fp_mgr = FingerprintManager(APP_DIR)
    fingerprint = fp_mgr.add_fingerprint(seed_phrase) or generate_fingerprint(
        seed_phrase
    )
    if fingerprint is None:
        fingerprint = profile_name
    profile_dir = APP_DIR / fingerprint
    profile_dir.mkdir(parents=True, exist_ok=True)

    seed_key = derive_key_from_password(DEFAULT_PASSWORD)
    seed_mgr = EncryptionManager(seed_key, profile_dir)
    seed_file = profile_dir / "parent_seed.enc"
    clear_path = profile_dir / "seed_phrase.txt"

    if seed_file.exists():
        try:
            current = seed_mgr.decrypt_parent_seed()
        except Exception:
            current = None
        if current != seed_phrase:
            seed_mgr.encrypt_parent_seed(seed_phrase)
    else:
        seed_mgr.encrypt_parent_seed(seed_phrase)

    if not clear_path.exists():
        clear_path.write_text(seed_phrase)
        clear_path.chmod(0o600)

    index_key = derive_index_key(seed_phrase)
    enc_mgr = EncryptionManager(index_key, profile_dir)
    vault = Vault(enc_mgr, profile_dir)
    cfg_mgr = ConfigManager(vault, profile_dir)
    # Store the default password hash so the profile can be opened
    hashed = bcrypt.hashpw(DEFAULT_PASSWORD.encode(), bcrypt.gensalt()).decode()
    cfg_mgr.set_password_hash(hashed)
    # Ensure stored iterations match the PBKDF2 work factor used above
    cfg_mgr.set_kdf_iterations(100_000)
    backup_mgr = BackupManager(profile_dir, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)
    return seed_phrase, entry_mgr, profile_dir, fingerprint, cfg_mgr


def random_secret(length: int = 16) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(random.choice(alphabet) for _ in range(length))


def populate(entry_mgr: EntryManager, seed: str, count: int) -> None:
    """Add ``count`` entries of varying types to the vault."""
    start_index = entry_mgr.get_next_index()
    for i in range(count):
        idx = start_index + i
        kind = idx % 9
        if kind == 0:
            entry_mgr.add_entry(
                label=f"site-{idx}.example.com",
                length=12,
                username=f"user{idx}",
                url=f"https://example{idx}.com",
                notes=f"Website account {idx}",
                custom_fields=[{"key": "id", "value": str(idx)}],
            )
        elif kind == 1:
            entry_mgr.add_totp(f"totp-generated-{idx}", seed)
        elif kind == 2:
            entry_mgr.add_totp(f"totp-imported-{idx}", seed, secret=random_secret())
        elif kind == 3:
            entry_mgr.add_ssh_key(f"ssh-{idx}", seed, notes=f"SSH key for server {idx}")
        elif kind == 4:
            entry_mgr.add_seed(
                f"derived-seed-{idx}", seed, words_num=24, notes=f"Seed {idx}"
            )
        elif kind == 5:
            entry_mgr.add_nostr_key(f"nostr-{idx}", notes=f"Nostr key {idx}")
        elif kind == 6:
            entry_mgr.add_pgp_key(
                f"pgp-{idx}",
                seed,
                user_id=f"user{idx}@example.com",
                notes=f"PGP key {idx}",
            )
        elif kind == 7:
            entry_mgr.add_key_value(
                f"kv-{idx}",
                random_secret(20),
                notes=f"Key/Value {idx}",
            )
        else:
            entry_mgr.add_managed_account(
                f"acct-{idx}",
                seed,
                notes=f"Managed account {idx}",
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Create or extend a SeedPass test profile (default PBKDF2 iterations:"
            " 100,000)"
        )
    )
    parser.add_argument(
        "--profile",
        default="test_profile",
        help="profile name inside ~/.seedpass/tests",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="number of entries to add",
    )
    args = parser.parse_args()

    seed, entry_mgr, dir_path, fingerprint, cfg_mgr = initialize_profile(args.profile)
    print(f"Using profile directory: {dir_path}")
    print(f"Parent seed: {seed}")
    if fingerprint:
        print(f"Fingerprint: {fingerprint}")
    populate(entry_mgr, seed, args.count)
    print(f"Added {args.count} entries.")

    encrypted = entry_mgr.vault.get_encrypted_index()
    if encrypted:
        client = NostrClient(
            entry_mgr.vault.encryption_manager,
            fingerprint or dir_path.name,
            parent_seed=seed,
            config_manager=cfg_mgr,
        )
        asyncio.run(client.publish_snapshot(encrypted))
        print("[+] Data synchronized to Nostr.")
        try:
            result = asyncio.run(client.fetch_latest_snapshot())
            if result:
                _, chunks = result
                retrieved = gzip.decompress(b"".join(chunks))
                if retrieved == encrypted:
                    print("[+] Verified snapshot retrieval.")
                else:
                    print(
                        f"[!] Retrieval failed: {client.last_error or 'data mismatch'}"
                    )
            else:
                print(f"[!] Retrieval failed: {client.last_error or 'data mismatch'}")
        except Exception as e:
            print(f"[!] Retrieval failed: {e}")
    else:
        print("[-] No encrypted index found to sync.")


if __name__ == "__main__":
    main()
