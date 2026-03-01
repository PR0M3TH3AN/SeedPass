from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR
from seedpass.core.entry_types import ALL_ENTRY_TYPES, EntryType

DEFAULT_EXPORT_POLICY: dict[str, Any] = {
    "allow_kinds": [
        EntryType.PASSWORD.value,
        EntryType.TOTP.value,
        EntryType.KEY_VALUE.value,
        EntryType.DOCUMENT.value,
    ],
    "allow_export_import": False,
    "export": {"allow_full_vault": False},
    "approvals": {
        "require_for": ["export", "reveal_parent_seed", "private_key_retrieval"]
    },
    "secret_isolation": {
        "enabled": True,
        "high_risk_kinds": [
            EntryType.SEED.value,
            EntryType.SSH.value,
            EntryType.PGP.value,
            EntryType.NOSTR.value,
            EntryType.MANAGED_ACCOUNT.value,
        ],
        "unlock_ttl_sec": 300,
    },
}

REASON_FULL_EXPORT_BLOCKED = "policy_deny:full_export_blocked"
REASON_KIND_NOT_ALLOWED = "policy_deny:kind_not_allowed"
REASON_EXPORT_ALLOWED = "policy_allow:export_allowed"
REASON_KIND_ALLOWED = "policy_allow:kind_allowed"
MANIFEST_VERSION = 2
REDACTED_SENTINEL = "[REDACTED_BY_POLICY]"


def _policy_path() -> Path:
    return APP_DIR / "agent_policy.json"


def _audit_key_path() -> Path:
    return APP_DIR / "agent_export_audit.key"


def _audit_log_path() -> Path:
    return APP_DIR / "agent_export_audit.log"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_or_create_audit_key() -> bytes:
    path = _audit_key_path()
    if path.exists():
        return path.read_bytes()
    _ensure_parent(path)
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def _previous_signature() -> str:
    path = _audit_log_path()
    if not path.exists():
        return "0" * 64
    try:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln]
        if not lines:
            return "0" * 64
        last = json.loads(lines[-1])
        return str(last.get("sig", "0" * 64))
    except Exception:
        return "0" * 64


def record_export_policy_event(event: str, details: dict[str, Any]) -> None:
    """Append signed export policy event to audit log (best-effort)."""
    key = _load_or_create_audit_key()
    prev_sig = _previous_signature()
    payload = {
        "timestamp_utc": _utcnow_iso(),
        "host": socket.gethostname(),
        "event": event,
        "details": details,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["sig"] = hmac.new(
        key, f"{prev_sig}{canonical}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    log_path = _audit_log_path()
    _ensure_parent(log_path)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")
    os.chmod(log_path, 0o600)


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
    approvals_cfg = data.get("approvals")
    if isinstance(approvals_cfg, dict):
        require_for = approvals_cfg.get("require_for")
        if isinstance(require_for, list):
            policy["approvals"] = {
                "require_for": [
                    str(v).strip().lower() for v in require_for if str(v).strip()
                ]
            }
    isolation_cfg = data.get("secret_isolation")
    if isinstance(isolation_cfg, dict):
        raw_high_risk = isolation_cfg.get("high_risk_kinds")
        if isinstance(raw_high_risk, list):
            high_risk_kinds = [
                str(v).strip().lower()
                for v in raw_high_risk
                if str(v).strip().lower()
                in {
                    EntryType.SEED.value,
                    EntryType.SSH.value,
                    EntryType.PGP.value,
                    EntryType.NOSTR.value,
                    EntryType.MANAGED_ACCOUNT.value,
                }
            ]
        else:
            high_risk_kinds = list(
                DEFAULT_EXPORT_POLICY["secret_isolation"]["high_risk_kinds"]
            )
        unlock_ttl_sec = int(
            isolation_cfg.get(
                "unlock_ttl_sec",
                DEFAULT_EXPORT_POLICY["secret_isolation"]["unlock_ttl_sec"],
            )
        )
        if unlock_ttl_sec < 1:
            unlock_ttl_sec = int(
                DEFAULT_EXPORT_POLICY["secret_isolation"]["unlock_ttl_sec"]
            )
        policy["secret_isolation"] = {
            "enabled": bool(isolation_cfg.get("enabled", True)),
            "high_risk_kinds": high_risk_kinds,
            "unlock_ttl_sec": unlock_ttl_sec,
        }
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


def evaluate_full_export(policy: dict[str, Any]) -> tuple[bool, str]:
    if full_export_allowed(policy):
        return True, REASON_EXPORT_ALLOWED
    return False, REASON_FULL_EXPORT_BLOCKED


def evaluate_kind_export(policy: dict[str, Any], kind: str) -> tuple[bool, str]:
    if kind_export_allowed(policy, kind):
        return True, REASON_KIND_ALLOWED
    return False, REASON_KIND_NOT_ALLOWED


def filter_index_for_allowed_kinds(
    index_data: dict[str, Any], kinds: set[str]
) -> dict[str, Any]:
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


def _policy_stamp(policy: dict[str, Any]) -> str:
    material = {
        "allow_kinds": sorted(list(allowed_kinds(policy))),
        "allow_export_import": bool(policy.get("allow_export_import", False)),
        "allow_full_vault": bool(
            policy.get("export", {}).get("allow_full_vault", False)
        ),
        "safe_output_default": bool(
            policy.get("output", {}).get("safe_output_default", True)
        ),
        "redact_fields": sorted(
            [str(v) for v in policy.get("output", {}).get("redact_fields", [])]
        ),
        "secret_isolation_enabled": bool(
            policy.get("secret_isolation", {}).get("enabled", True)
        ),
        "secret_isolation_high_risk_kinds": sorted(
            [
                str(v)
                for v in policy.get("secret_isolation", {}).get("high_risk_kinds", [])
            ]
        ),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _sorted_index_keys(indexes: list[str]) -> list[str]:
    def _key(value: str) -> tuple[int, int, str]:
        try:
            return (0, int(value), value)
        except Exception:
            return (1, 0, value)

    return sorted([str(v) for v in indexes], key=_key)


def compute_policy_stamp(policy: dict[str, Any]) -> str:
    """Return deterministic hash over export-relevant policy controls."""
    return _policy_stamp(policy)


def _redacted_copy(entry: dict[str, Any], redacted_fields: set[str]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key, value in entry.items():
        if key in redacted_fields:
            copied[key] = REDACTED_SENTINEL
        else:
            copied[key] = value
    return copied


def build_policy_filtered_export_package(
    index_data: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    kinds = allowed_kinds(policy)
    redacted_fields = {
        str(v) for v in policy.get("output", {}).get("redact_fields", []) if str(v)
    }
    entries = index_data.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}

    filtered_entries: dict[str, dict[str, Any]] = {}
    excluded = 0
    for idx, entry in entries.items():
        if not isinstance(entry, dict):
            excluded += 1
            continue
        kind = str(entry.get("kind", entry.get("type", "")))
        if kind not in kinds:
            excluded += 1
            continue
        filtered_entries[str(idx)] = _redacted_copy(entry, redacted_fields)
    sorted_indexes = _sorted_index_keys(list(filtered_entries.keys()))
    entries_canonical = _canonical_json(
        {idx: filtered_entries[idx] for idx in sorted_indexes}
    )

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "mode": "policy_filtered",
        "policy_stamp": _policy_stamp(policy),
        "allow_kinds": sorted(list(kinds)),
        "redacted_fields": sorted(list(redacted_fields)),
        "safe_output_default": bool(
            policy.get("output", {}).get("safe_output_default", True)
        ),
        "included_entry_count": len(filtered_entries),
        "excluded_entry_count": int(excluded),
        "included_entry_indexes": sorted_indexes,
        "entries_sha256": hashlib.sha256(entries_canonical.encode("utf-8")).hexdigest(),
        "source_schema_version": int(index_data.get("schema_version", 1)),
    }
    return {
        "schema_version": int(index_data.get("schema_version", 1)),
        "_export_manifest": manifest,
        "entries": filtered_entries,
    }


def verify_filtered_export_package(
    package: dict[str, Any], policy: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Verify filtered export package shape and policy stamp compatibility."""
    errors: list[str] = []
    if not isinstance(package, dict):
        return False, ["package_not_object"]
    manifest = package.get("_export_manifest")
    if not isinstance(manifest, dict):
        return False, ["missing_manifest"]
    if manifest.get("mode") != "policy_filtered":
        errors.append("invalid_mode")
    manifest_version = _safe_int(manifest.get("manifest_version", 0), default=0)
    if manifest_version not in {1, MANIFEST_VERSION}:
        errors.append("invalid_manifest_version")
    entries = package.get("entries")
    if not isinstance(entries, dict):
        errors.append("entries_not_object")
        entries = {}

    expected_stamp = compute_policy_stamp(policy)
    if str(manifest.get("policy_stamp", "")) != expected_stamp:
        errors.append("policy_stamp_mismatch")

    listed_indexes = manifest.get("included_entry_indexes", [])
    if not isinstance(listed_indexes, list):
        errors.append("invalid_included_entry_indexes")
        listed_indexes = []
    listed_indexes_str = [str(v) for v in listed_indexes]
    actual_indexes = _sorted_index_keys(list(entries.keys()))
    if listed_indexes_str != actual_indexes:
        errors.append("included_entry_indexes_mismatch")

    included_count = _safe_int(manifest.get("included_entry_count", -1), default=-1)
    if included_count != len(actual_indexes):
        errors.append("included_entry_count_mismatch")

    excluded_count = _safe_int(manifest.get("excluded_entry_count", -1), default=-1)
    if excluded_count < 0:
        errors.append("invalid_excluded_entry_count")

    allow_kinds_manifest = manifest.get("allow_kinds", [])
    if not isinstance(allow_kinds_manifest, list):
        errors.append("invalid_allow_kinds")
        allow_kinds_manifest = []
    expected_kinds = sorted(list(allowed_kinds(policy)))
    if sorted([str(v) for v in allow_kinds_manifest]) != expected_kinds:
        errors.append("allow_kinds_mismatch")

    manifest_redacted_fields = manifest.get("redacted_fields", [])
    if not isinstance(manifest_redacted_fields, list):
        errors.append("invalid_redacted_fields")
        manifest_redacted_fields = []
    expected_redacted_fields = sorted(
        [str(v) for v in policy.get("output", {}).get("redact_fields", []) if str(v)]
    )
    if sorted([str(v) for v in manifest_redacted_fields]) != expected_redacted_fields:
        errors.append("redacted_fields_mismatch")

    source_schema_version = _safe_int(
        manifest.get("source_schema_version", -1), default=-1
    )
    package_schema_version = _safe_int(package.get("schema_version", -2), default=-2)
    if package_schema_version != source_schema_version:
        errors.append("source_schema_version_mismatch")

    allowed_kind_set = set(expected_kinds)
    redacted_fields_set = set(expected_redacted_fields)
    for idx, entry in entries.items():
        if not isinstance(entry, dict):
            errors.append("entry_not_object")
            continue
        kind = str(entry.get("kind", entry.get("type", "")))
        if kind not in allowed_kind_set:
            errors.append("entry_kind_not_allowed")
            break
        for field in redacted_fields_set:
            if field in entry and entry.get(field) != REDACTED_SENTINEL:
                errors.append("entry_redaction_mismatch")
                break

    if manifest_version >= 2:
        expected_entries_sha = hashlib.sha256(
            _canonical_json(
                {idx: entries[idx] for idx in _sorted_index_keys(list(entries.keys()))}
            ).encode("utf-8")
        ).hexdigest()
        if str(manifest.get("entries_sha256", "")) != expected_entries_sha:
            errors.append("entries_hash_mismatch")

    return len(errors) == 0, errors
