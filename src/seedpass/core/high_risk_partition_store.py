from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

PARTITION_FILENAME = "seedpass_high_risk_entries.json.enc"


def _partition_path(fingerprint_dir: Path) -> Path:
    return Path(fingerprint_dir) / PARTITION_FILENAME


def _fernet_for_tag(partition_key_tag: str) -> Fernet:
    raw = hashlib.sha256(partition_key_tag.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def load_partition_entries(
    fingerprint_dir: Path, partition_key_tag: str
) -> dict[str, dict[str, Any]]:
    path = _partition_path(fingerprint_dir)
    if not path.exists():
        return {}
    fernet = _fernet_for_tag(partition_key_tag)
    blob = path.read_bytes()
    try:
        payload = fernet.decrypt(blob).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("invalid_partition_key_tag") from exc
    data = json.loads(payload)
    if not isinstance(data, dict):
        return {}
    entries = data.get("entries", {})
    if not isinstance(entries, dict):
        return {}
    return {str(k): v for k, v in entries.items() if isinstance(v, dict)}


def save_partition_entries(
    fingerprint_dir: Path,
    partition_key_tag: str,
    entries: dict[str, dict[str, Any]],
) -> Path:
    path = _partition_path(fingerprint_dir)
    fernet = _fernet_for_tag(partition_key_tag)
    payload = {
        "schema_version": 1,
        "partition": "high_risk",
        "updated_at_utc": time.time(),
        "entries": entries,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(fernet.encrypt(raw))
    return path


def load_partition_entry(
    fingerprint_dir: Path, partition_key_tag: str, index: int
) -> dict[str, Any] | None:
    entries = load_partition_entries(fingerprint_dir, partition_key_tag)
    return entries.get(str(index))


def migrate_high_risk_entries(
    *,
    vault: Any,
    fingerprint_dir: Path,
    partition_key_tag: str,
    high_risk_kinds: set[str],
) -> dict[str, Any]:
    index = vault.load_index()
    entries = index.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    partition_entries = load_partition_entries(fingerprint_dir, partition_key_tag)

    moved_indexes: list[str] = []
    for idx, entry in list(entries.items()):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", entry.get("type", ""))).strip().lower()
        if kind not in high_risk_kinds:
            continue
        idx_s = str(idx)
        partition_entries[idx_s] = entry
        entries[idx_s] = {
            "type": kind,
            "kind": kind,
            "index": int(entry.get("index", idx)),
            "label": str(entry.get("label", "")),
            "archived": bool(entry.get("archived", False)),
            "partition": "high_risk",
            "partition_ref": idx_s,
            "modified_ts": int(entry.get("modified_ts", int(time.time()))),
        }
        moved_indexes.append(idx_s)

    index["entries"] = entries
    if moved_indexes:
        vault.save_index(index)
        save_partition_entries(fingerprint_dir, partition_key_tag, partition_entries)

    return {
        "moved_count": len(moved_indexes),
        "moved_indexes": sorted(moved_indexes, key=lambda v: int(v)),
        "partition_file": str(_partition_path(fingerprint_dir)),
    }
