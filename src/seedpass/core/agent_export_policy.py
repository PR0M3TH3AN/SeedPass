from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from constants import APP_DIR
from seedpass.core.entry_types import ALL_ENTRY_TYPES, EntryType

DEFAULT_EXPORT_POLICY: dict[str, Any] = {
    "allow_kinds": [
        EntryType.PASSWORD.value,
        EntryType.TOTP.value,
        EntryType.KEY_VALUE.value,
    ],
    "allow_export_import": False,
    "export": {"allow_full_vault": False},
}


def _policy_path() -> Path:
    return APP_DIR / "agent_policy.json"


def load_export_policy() -> dict[str, Any]:
    path = _policy_path()
    if not path.exists():
        return dict(DEFAULT_EXPORT_POLICY)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULT_EXPORT_POLICY)
    if not isinstance(data, dict):
        return dict(DEFAULT_EXPORT_POLICY)

    policy = dict(DEFAULT_EXPORT_POLICY)
    allow_kinds = data.get("allow_kinds")
    if isinstance(allow_kinds, list):
        policy["allow_kinds"] = [
            str(v) for v in allow_kinds if str(v) in ALL_ENTRY_TYPES
        ]
    if isinstance(data.get("allow_export_import"), bool):
        policy["allow_export_import"] = data["allow_export_import"]
    export_cfg = data.get("export")
    if isinstance(export_cfg, dict):
        policy["export"] = {
            "allow_full_vault": bool(export_cfg.get("allow_full_vault", False))
        }
    elif isinstance(data.get("allow_export_import"), bool):
        policy["export"] = {"allow_full_vault": bool(data["allow_export_import"])}
    return policy


def full_export_allowed(policy: dict[str, Any]) -> bool:
    return bool(
        policy.get("allow_export_import", False)
        or policy.get("export", {}).get("allow_full_vault", False)
    )


def allowed_kinds(policy: dict[str, Any]) -> set[str]:
    kinds = policy.get("allow_kinds", [])
    if not isinstance(kinds, list):
        return set()
    return {str(v) for v in kinds if str(v) in ALL_ENTRY_TYPES}


def kind_export_allowed(policy: dict[str, Any], kind: str) -> bool:
    return kind in allowed_kinds(policy)


def filter_index_for_allowed_kinds(index_data: dict[str, Any], kinds: set[str]) -> dict[str, Any]:
    entries = index_data.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    filtered_entries = {}
    for idx, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", entry.get("type", "")))
        if kind in kinds:
            filtered_entries[str(idx)] = entry
    return {
        "schema_version": int(index_data.get("schema_version", 1)),
        "entries": filtered_entries,
    }
