from __future__ import annotations

import hashlib
import json
from typing import Any

TOMBSTONE_RETENTION_CAP = 2048


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _entry_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _entry_ts(entry: dict[str, Any]) -> int:
    return _safe_int(entry.get("modified_ts", 0), default=0)


def _safe_int(raw: Any, *, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        return int(default)


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _entry_kind(entry: dict[str, Any]) -> str:
    return str(entry.get("kind", entry.get("type", "password"))).strip().lower()


def _is_deleted_entry(entry: dict[str, Any]) -> bool:
    return bool(entry.get("_deleted", False) or entry.get("deleted", False))


def _entry_event_hash(entry: dict[str, Any]) -> str:
    marker = {"entry": entry, "kind": "entry"}
    return hashlib.sha256(_canonical(marker).encode("utf-8")).hexdigest()


def _tombstone_event_hash(record: dict[str, Any], idx: str) -> str:
    provided = str(record.get("event_hash", "")).strip().lower()
    if provided:
        return provided
    marker = {
        "kind": "tombstone",
        "index": str(idx),
        "deleted_ts": _safe_int(record.get("deleted_ts", 0), default=0),
        "entry_hash": str(record.get("entry_hash", "")),
    }
    return hashlib.sha256(_canonical(marker).encode("utf-8")).hexdigest()


def _prefer_tombstone(
    current: dict[str, Any], incoming: dict[str, Any], idx: str
) -> bool:
    cur_ts = _safe_int(current.get("deleted_ts", 0), default=0)
    inc_ts = _safe_int(incoming.get("deleted_ts", 0), default=0)
    if inc_ts != cur_ts:
        return inc_ts > cur_ts
    return _tombstone_event_hash(incoming, idx) > _tombstone_event_hash(current, idx)


def _normalize_tombstones(value: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict):
        return out
    for k, v in value.items():
        if not isinstance(v, dict):
            continue
        idx = str(k)
        ts_raw = v.get("deleted_ts", 0)
        deleted_ts = _safe_int(ts_raw, default=0)
        if deleted_ts <= 0:
            continue
        out[idx] = {
            "deleted_ts": deleted_ts,
            "entry_hash": str(v.get("entry_hash", "")),
            "event_hash": str(v.get("event_hash", "")),
            "source": str(v.get("source", "")),
        }
    return out


def _merge_tombstones(
    current: dict[str, dict[str, Any]], incoming: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    merged = dict(current)
    for idx, rec in incoming.items():
        cur = merged.get(idx)
        if cur is None or _prefer_tombstone(cur, rec, idx):
            merged[idx] = dict(rec)
    return merged


def _max_entry_ts(entries: dict[str, Any]) -> int:
    max_ts = 0
    for value in entries.values():
        if isinstance(value, dict):
            ts = _entry_ts(value)
            if ts > max_ts:
                max_ts = ts
    return max_ts


def _max_tombstone_ts(tombstones: dict[str, dict[str, Any]]) -> int:
    max_ts = 0
    for record in tombstones.values():
        if isinstance(record, dict):
            ts = _safe_int(record.get("deleted_ts", 0), default=0)
            if ts > max_ts:
                max_ts = ts
    return max_ts


def _prefer_entry(current: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Return True when incoming should replace current deterministically.

    Order-independent rule:
    1) higher modified_ts wins
    2) on equal ts, lexicographically larger canonical entry hash wins
    """
    cur_ts = _entry_ts(current)
    inc_ts = _entry_ts(incoming)
    if inc_ts != cur_ts:
        return inc_ts > cur_ts
    return _entry_hash(incoming) > _entry_hash(current)


def _union_fields_for_kind(kind: str) -> list[str]:
    common = ["notes", "tags", "custom_fields", "links"]
    matrix = {
        "password": ["username", "url"],
        "totp": ["issuer"],
        "key_value": ["key", "value"],
        "managed_account": ["value", "user_id"],
        "ssh": ["username", "public_key", "algorithm", "key_type"],
        "pgp": ["public_key", "key_type"],
        "nostr": ["npub", "public_key"],
        "seed": ["path", "network", "coin_type"],
        "document": ["content", "file_type"],
    }
    return matrix.get(kind, []) + common


def _merge_list_union(preferred: Any, other: Any) -> Any:
    if isinstance(preferred, list) and isinstance(other, list):
        seen: dict[str, Any] = {}
        for item in preferred + other:
            key = _canonical(item)
            seen[key] = item
        return [seen[k] for k in sorted(seen.keys())]
    return preferred


def _merge_equal_ts_entries(
    preferred: dict[str, Any], other: dict[str, Any], *, ts: int
) -> dict[str, Any]:
    """Merge entries at equal timestamp with deterministic field-level rules."""
    merged = dict(preferred)
    union_fields = _union_fields_for_kind(_entry_kind(merged))
    for field in union_fields:
        pv = merged.get(field)
        ov = other.get(field)
        if field in ("tags", "custom_fields", "links"):
            merged[field] = _merge_list_union(pv, ov)
            continue
        if _is_empty(pv) and not _is_empty(ov):
            merged[field] = ov

    # Prefer conservative archival behavior at equal timestamp.
    if "archived" in preferred or "archived" in other:
        merged["archived"] = bool(preferred.get("archived", False)) or bool(
            other.get("archived", False)
        )
    merged["modified_ts"] = int(ts)
    return merged


def merge_index_payloads(
    current: dict[str, Any], incoming: dict[str, Any], *, source_tag: str = ""
) -> dict[str, Any]:
    """Merge two index payloads using deterministic conflict resolution."""
    out = dict(current) if isinstance(current, dict) else {}
    cur_entries = out.get("entries", {})
    if not isinstance(cur_entries, dict):
        cur_entries = {}
    inc_entries = incoming.get("entries", {}) if isinstance(incoming, dict) else {}
    if not isinstance(inc_entries, dict):
        inc_entries = {}
    cur_meta = (
        out.get("_sync_meta", {}) if isinstance(out.get("_sync_meta"), dict) else {}
    )
    inc_meta = (
        incoming.get("_sync_meta", {})
        if isinstance(incoming, dict) and isinstance(incoming.get("_sync_meta"), dict)
        else {}
    )
    cur_tombstones = _normalize_tombstones(cur_meta.get("tombstones", {}))
    inc_tombstones = _normalize_tombstones(inc_meta.get("tombstones", {}))
    tombstones = _merge_tombstones(cur_tombstones, inc_tombstones)

    for idx, inc_entry in inc_entries.items():
        if not isinstance(inc_entry, dict):
            continue
        key = str(idx)
        if _is_deleted_entry(inc_entry):
            delete_ts = _entry_ts(inc_entry)
            if delete_ts <= 0:
                delete_ts = max(
                    _safe_int(cur_meta.get("last_merge_ts", 0), default=0),
                    _safe_int(inc_meta.get("last_merge_ts", 0), default=0),
                    _max_entry_ts(cur_entries),
                    _max_entry_ts(inc_entries),
                    _max_tombstone_ts(tombstones),
                )
                if delete_ts <= 0:
                    delete_ts = 1
            tombstones = _merge_tombstones(
                tombstones,
                {
                    key: {
                        "deleted_ts": delete_ts,
                        "entry_hash": str(inc_entry.get("entry_hash", "")),
                        "event_hash": _entry_event_hash(inc_entry),
                        "source": source_tag,
                    }
                },
            )
            cur_entries.pop(key, None)
            continue
        cur_entry = cur_entries.get(key)
        if not isinstance(cur_entry, dict):
            cur_entries[key] = inc_entry
            continue
        cur_ts = _entry_ts(cur_entry)
        inc_ts = _entry_ts(inc_entry)
        if cur_ts == inc_ts:
            if _prefer_entry(cur_entry, inc_entry):
                cur_entries[key] = _merge_equal_ts_entries(
                    inc_entry, cur_entry, ts=inc_ts
                )
            else:
                cur_entries[key] = _merge_equal_ts_entries(
                    cur_entry, inc_entry, ts=cur_ts
                )
            continue
        if _prefer_entry(cur_entry, inc_entry):
            cur_entries[key] = inc_entry

    # Apply tombstones deterministically after entry merge.
    for idx, rec in list(tombstones.items()):
        entry = cur_entries.get(idx)
        if not isinstance(entry, dict):
            continue
        e_ts = _entry_ts(entry)
        d_ts = _safe_int(rec.get("deleted_ts", 0), default=0)
        if e_ts > d_ts:
            tombstones.pop(idx, None)
            continue
        if e_ts < d_ts:
            cur_entries.pop(idx, None)
            continue
        # Equal timestamp: compare event hashes to break ties.
        if _tombstone_event_hash(rec, idx) > _entry_event_hash(entry):
            cur_entries.pop(idx, None)
        else:
            tombstones.pop(idx, None)

    out["entries"] = cur_entries
    if isinstance(incoming, dict) and "schema_version" in incoming:
        out["schema_version"] = max(
            int(out.get("schema_version", 0)), int(incoming.get("schema_version", 0))
        )

    meta = out.get("_sync_meta", {})
    if not isinstance(meta, dict):
        meta = {}
    sources = meta.get("sources", [])
    if not isinstance(sources, list):
        sources = []
    if source_tag and source_tag not in sources:
        sources.append(source_tag)
    sources = sorted(set(str(v) for v in sources if str(v)))
    if tombstones:
        tomb_items = sorted(
            tombstones.items(),
            key=lambda item: (
                _safe_int(item[1].get("deleted_ts", 0), default=0),
                item[0],
            ),
        )
        if len(tomb_items) > TOMBSTONE_RETENTION_CAP:
            tomb_items = tomb_items[-TOMBSTONE_RETENTION_CAP:]
        tombstones = {k: v for k, v in tomb_items}
    last_merge_ts = max(
        _safe_int(meta.get("last_merge_ts", 0), default=0),
        _safe_int(inc_meta.get("last_merge_ts", 0), default=0),
        _max_entry_ts(cur_entries),
        _max_tombstone_ts(tombstones),
    )
    meta.update(
        {
            "strategy": "modified_ts_hash_tombstone_v2",
            "last_merge_ts": last_merge_ts,
            "source_count": len(sources),
            "sources": sources[-32:],
            "tombstones": tombstones,
        }
    )
    out["_sync_meta"] = meta
    return out
