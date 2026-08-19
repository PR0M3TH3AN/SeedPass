# portable_backup.py
"""Export and import encrypted profile backups."""

from __future__ import annotations

import base64
import json
import re
import logging
import os
import time
import asyncio
from enum import Enum
from pathlib import Path

from .vault import Vault
from .backup import BackupManager
from nostr.client import NostrClient
from utils.key_derivation import (
    derive_index_key,
    EncryptionMode,
)
from .encryption import EncryptionManager
from utils.checksum import json_checksum, canonical_json_dumps
from utils.fingerprint import generate_fingerprint
from .state_manager import StateManager
from .derivation_collisions import find_derivation_collisions
from .errors import ProfileMismatchError

from termcolor import colored

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
EXPORT_NAME_TEMPLATE = "seedpass_export_{ts}.json"


class PortableMode(Enum):
    """Encryption mode for portable exports."""

    SEED_ONLY = EncryptionMode.SEED_ONLY.value
    NONE = "none"


def _derive_export_key(seed: str) -> bytes:
    """Derive the Fernet key for the export payload."""

    return derive_index_key(seed)


def export_backup(
    vault: Vault,
    backup_manager: BackupManager,
    dest_path: Path | None = None,
    *,
    publish: bool = False,
    parent_seed: str | None = None,
    encrypt: bool = True,
) -> Path:
    """Export the current vault state to a portable file.

    When ``encrypt`` is ``True`` (the default) the payload is encrypted with a
    key derived from the parent seed.  When ``encrypt`` is ``False`` the payload
    is written in plaintext and the wrapper records an ``encryption_mode`` of
    :data:`PortableMode.NONE`.
    """

    if dest_path is None:
        ts = int(time.time())
        dest_dir = vault.fingerprint_dir / "exports"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / EXPORT_NAME_TEMPLATE.format(ts=ts)

    index_data = vault.load_index()
    canonical = canonical_json_dumps(index_data)

    if encrypt:
        seed = (
            parent_seed
            if parent_seed is not None
            else vault.encryption_manager.decrypt_parent_seed()
        )
        key = _derive_export_key(seed)
        enc_mgr = EncryptionManager(key, vault.fingerprint_dir)
        payload_bytes = enc_mgr.encrypt_data(canonical.encode("utf-8"))
        mode = PortableMode.SEED_ONLY
        cipher = "aes-gcm"
    else:
        payload_bytes = canonical.encode("utf-8")
        mode = PortableMode.NONE
        cipher = "none"

    checksum = json_checksum(index_data)

    wrapper = {
        "format_version": FORMAT_VERSION,
        "created_at": int(time.time()),
        "fingerprint": vault.fingerprint_dir.name,
        "encryption_mode": mode.value,
        "cipher": cipher,
        "checksum": checksum,
        "payload": base64.b64encode(payload_bytes).decode("utf-8"),
    }

    json_bytes = json.dumps(wrapper, indent=2).encode("utf-8")
    dest_path.write_bytes(json_bytes)
    os.chmod(dest_path, 0o600)
    backup_manager._create_additional_backup(dest_path)

    if publish:
        encrypted = vault.encryption_manager.encrypt_data(json_bytes)
        enc_file = dest_path.with_suffix(dest_path.suffix + ".enc")
        enc_file.write_bytes(encrypted)
        os.chmod(enc_file, 0o600)
        try:
            idx = StateManager(vault.fingerprint_dir).state.get("nostr_account_idx", 0)
            client = NostrClient(
                vault.encryption_manager,
                vault.fingerprint_dir.name,
                config_manager=backup_manager.config_manager,
                account_index=idx,
            )
            asyncio.run(client.publish_snapshot(encrypted))
        except Exception:
            logger.error("Failed to publish backup via Nostr", exc_info=True)

    return dest_path


_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{16}$")


def _looks_like_fingerprint(value: str) -> bool:
    """Is this string a SeedPass profile fingerprint?

    ``generate_fingerprint`` produces 16 uppercase hex characters. Anything
    else in a backup's ``fingerprint`` field tells us nothing about which seed
    produced it.
    """
    return bool(_FINGERPRINT_RE.match(value))


def import_backup(
    vault: Vault,
    backup_manager: BackupManager,
    path: Path,
    parent_seed: str | None = None,
    allow_fingerprint_mismatch: bool = False,
) -> None:
    """Import a portable backup file and replace the current index.

    ``allow_fingerprint_mismatch`` permits importing a backup taken from a
    different profile. See the fingerprint check below for why that is not the
    default.
    """

    raw = Path(path).read_bytes()
    if path.suffix.endswith(".enc"):
        raw = vault.encryption_manager.decrypt_data(raw, context=str(path))

    wrapper = json.loads(raw.decode("utf-8"))
    if wrapper.get("format_version") != FORMAT_VERSION:
        raise ValueError("Unsupported backup format")

    # A seed-only backup is bound to its seed implicitly -- the wrong seed
    # cannot decrypt it. A plaintext one carries no such binding: it imports
    # cleanly into any profile, and every derived entry (passwords, SSH, PGP,
    # seeds) is then re-derived from THIS profile's seed, silently producing
    # different secrets than the backup was taken to preserve. Nothing errors;
    # the user simply gets wrong passwords.
    #
    # The comparison is against the fingerprint DERIVED FROM THE SEED being
    # imported under, not against the profile directory's name. In production
    # those are the same string -- a profile directory is named for its
    # fingerprint -- but the question worth asking is "was this backup made
    # from my seed?", and only the seed can answer it. Comparing directory
    # names would refuse a legitimate restore of the same seed into a freshly
    # named profile.
    #
    # Only enforced when the wrapper records something that actually is a
    # fingerprint. A backup carrying some other label gives no evidence about
    # which seed made it, and refusing on no evidence would block restores
    # without making anyone safer.
    source_fingerprint = str(wrapper.get("fingerprint") or "")
    seed_for_check = (
        parent_seed
        if parent_seed is not None
        else vault.encryption_manager.decrypt_parent_seed()
    )
    target_fingerprint = generate_fingerprint(seed_for_check) or ""
    if (
        _looks_like_fingerprint(source_fingerprint)
        and source_fingerprint != target_fingerprint
        and not allow_fingerprint_mismatch
    ):
        raise ProfileMismatchError(
            f"Backup belongs to profile {source_fingerprint}, but the target "
            f"is {target_fingerprint}. Importing it would re-derive every "
            f"secret from the target's seed, silently producing different "
            f"passwords than the ones in the backup. Import into the matching "
            f"profile, or pass allow_fingerprint_mismatch=True if that is "
            f"really what you want."
        )

    mode = wrapper.get("encryption_mode")
    payload = base64.b64decode(wrapper["payload"])

    if mode == PortableMode.SEED_ONLY.value:
        seed = (
            parent_seed
            if parent_seed is not None
            else vault.encryption_manager.decrypt_parent_seed()
        )
        key = _derive_export_key(seed)
        enc_mgr = EncryptionManager(key, vault.fingerprint_dir)
        enc_mgr._legacy_migrate_flag = False
        index_bytes = enc_mgr.decrypt_data(payload, context="backup payload")
    elif mode == PortableMode.NONE.value:
        index_bytes = payload
    else:
        raise ValueError("Unsupported encryption mode")

    index = json.loads(index_bytes.decode("utf-8"))

    checksum = json_checksum(index)
    if checksum != wrapper.get("checksum"):
        raise ValueError("Checksum mismatch")

    # Two different-kind entries at one BIP-85 app-32 index derive the same
    # key. Neither implementation can create that state; it arrives with data,
    # and an import is one of the ways it arrives. Report rather than refuse:
    # the vault is still importable and the user may need it back.
    for collision in find_derivation_collisions(index):
        logger.warning("%s", collision.message)
        print(colored(f"Warning: {collision.message}", "yellow"))

    backup_manager.create_backup()
    vault.save_index(index)
