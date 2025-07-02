# portable_backup.py
"""Export and import encrypted profile backups."""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path

from password_manager.vault import Vault
from password_manager.backup import BackupManager
from nostr.client import NostrClient
from utils.key_derivation import (
    derive_index_key,
    EncryptionMode,
    DEFAULT_ENCRYPTION_MODE,
)
from utils.password_prompt import prompt_existing_password
from password_manager.encryption import EncryptionManager
from utils.checksum import json_checksum, canonical_json_dumps

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
EXPORT_NAME_TEMPLATE = "seedpass_export_{ts}.json"


class PortableMode(Enum):
    """Encryption mode for portable exports."""

    SEED_ONLY = EncryptionMode.SEED_ONLY.value
    SEED_PLUS_PW = EncryptionMode.SEED_PLUS_PW.value
    PW_ONLY = EncryptionMode.PW_ONLY.value


def _derive_export_key(
    seed: str,
    mode: PortableMode,
    password: str | None = None,
) -> bytes:
    """Derive the Fernet key for the export payload."""

    enc_mode = EncryptionMode(mode.value)
    return derive_index_key(seed, password, enc_mode)


def export_backup(
    vault: Vault,
    backup_manager: BackupManager,
    mode: PortableMode = PortableMode.SEED_ONLY,
    dest_path: Path | None = None,
    *,
    publish: bool = False,
) -> Path:
    """Export the current vault state to a portable encrypted file."""

    if dest_path is None:
        ts = int(time.time())
        dest_dir = vault.fingerprint_dir / "exports"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / EXPORT_NAME_TEMPLATE.format(ts=ts)

    index_data = vault.load_index()
    seed = vault.encryption_manager.decrypt_parent_seed()
    password = None
    if mode in (PortableMode.SEED_PLUS_PW, PortableMode.PW_ONLY):
        password = prompt_existing_password("Enter your master password: ")

    key = _derive_export_key(seed, mode, password)
    enc_mgr = EncryptionManager(key, vault.fingerprint_dir)

    canonical = canonical_json_dumps(index_data)
    payload_bytes = enc_mgr.encrypt_data(canonical.encode("utf-8"))
    checksum = json_checksum(index_data)

    wrapper = {
        "format_version": FORMAT_VERSION,
        "created_at": int(time.time()),
        "fingerprint": vault.fingerprint_dir.name,
        "encryption_mode": mode.value,
        "cipher": "fernet",
        "checksum": checksum,
        "payload": base64.b64encode(payload_bytes).decode("utf-8"),
    }

    json_bytes = json.dumps(wrapper, indent=2).encode("utf-8")
    dest_path.write_bytes(json_bytes)
    os.chmod(dest_path, 0o600)

    if publish:
        encrypted = vault.encryption_manager.encrypt_data(json_bytes)
        enc_file = dest_path.with_suffix(dest_path.suffix + ".enc")
        enc_file.write_bytes(encrypted)
        os.chmod(enc_file, 0o600)
        try:
            client = NostrClient(vault.encryption_manager, vault.fingerprint_dir.name)
            client.publish_json_to_nostr(encrypted)
        except Exception:
            logger.error("Failed to publish backup via Nostr", exc_info=True)

    return dest_path


def import_backup(
    vault: Vault,
    backup_manager: BackupManager,
    path: Path,
) -> None:
    """Import a portable backup file and replace the current index."""

    raw = Path(path).read_bytes()
    if path.suffix.endswith(".enc"):
        raw = vault.encryption_manager.decrypt_data(raw)

    wrapper = json.loads(raw.decode("utf-8"))
    if wrapper.get("format_version") != FORMAT_VERSION:
        raise ValueError("Unsupported backup format")

    mode = PortableMode(wrapper.get("encryption_mode", PortableMode.SEED_ONLY.value))
    payload = base64.b64decode(wrapper["payload"])

    seed = vault.encryption_manager.decrypt_parent_seed()
    password = None
    if mode in (PortableMode.SEED_PLUS_PW, PortableMode.PW_ONLY):
        password = prompt_existing_password("Enter your master password: ")

    key = _derive_export_key(seed, mode, password)
    enc_mgr = EncryptionManager(key, vault.fingerprint_dir)
    index_bytes = enc_mgr.decrypt_data(payload)
    index = json.loads(index_bytes.decode("utf-8"))

    checksum = json_checksum(index)
    if checksum != wrapper.get("checksum"):
        raise ValueError("Checksum mismatch")

    backup_manager.create_backup()
    vault.save_index(index)
