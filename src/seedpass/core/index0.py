from __future__ import annotations

import hashlib
import json
from typing import Any

INDEX0_SCHEMA_VERSION = 1
LOCAL_ONLY_VIEW_TYPES = {"hot_nodes", "conversation_index", "semantic_neighbors"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256_hex(value: Any) -> str:
    if isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = _canonical(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_string(value: Any) -> str:
    return str(value).strip()


def _safe_int(raw: Any, *, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        return int(default)


def _normalize_tags(raw_tags: Any) -> list[str]:
    if not isinstance(raw_tags, list):
        return []
    out = sorted({_normalize_string(tag) for tag in raw_tags if _normalize_string(tag)})
    return out


def _normalize_links(raw_links: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_links, list):
        return []
    out: dict[str, dict[str, Any]] = {}
    for item in raw_links:
        if not isinstance(item, dict):
            continue
        target_id = _normalize_string(item.get("target_id", ""))
        relation = _normalize_string(item.get("relation", ""))
        note = _normalize_string(item.get("note", ""))
        if not target_id or not relation:
            continue
        normalized = {"target_id": target_id, "relation": relation}
        if note:
            normalized["note"] = note
        out[_canonical(normalized)] = normalized
    return [out[key] for key in sorted(out.keys())]


def _normalize_mapping(raw: Any) -> dict[str, Any]:
    return dict(raw) if isinstance(raw, dict) else {}


def normalize_index0(raw: Any) -> dict[str, Any]:
    data = dict(raw) if isinstance(raw, dict) else {}
    normalized = {
        "schema_version": max(
            INDEX0_SCHEMA_VERSION,
            _safe_int(data.get("schema_version", INDEX0_SCHEMA_VERSION), default=1),
        ),
        "events": {},
        "checkpoints": {},
        "canonical_views": {},
        "view_manifest": {},
        "heads": {},
        "stats": {},
    }
    for event_id, event in _normalize_mapping(data.get("events")).items():
        normalized_event = normalize_index0_event(event)
        if normalized_event is None:
            continue
        normalized["events"][str(event_id)] = normalized_event
    for checkpoint_id, checkpoint in _normalize_mapping(
        data.get("checkpoints")
    ).items():
        normalized_checkpoint = normalize_index0_checkpoint(checkpoint)
        if normalized_checkpoint is None:
            continue
        normalized["checkpoints"][str(checkpoint_id)] = normalized_checkpoint
    view_manifest = normalize_view_manifest(data.get("view_manifest"))
    normalized["view_manifest"] = view_manifest
    for view_id, view in _normalize_mapping(data.get("canonical_views")).items():
        normalized_view = normalize_canonical_view(view, view_manifest=view_manifest)
        if normalized_view is None:
            continue
        normalized["canonical_views"][str(view_id)] = normalized_view
    for writer_id, head in _normalize_mapping(data.get("heads")).items():
        normalized_head = normalize_head(head)
        if normalized_head is None:
            continue
        normalized["heads"][str(writer_id)] = normalized_head
    normalized["stats"] = recompute_index0_stats(normalized)
    return normalized


def ensure_index0_payload(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data) if isinstance(data, dict) else {}
    system = dict(out.get("_system")) if isinstance(out.get("_system"), dict) else {}
    system["index0"] = normalize_index0(system.get("index0"))
    out["_system"] = system
    return out


def normalize_view_manifest(raw: Any) -> dict[str, Any]:
    data = dict(raw) if isinstance(raw, dict) else {}
    canonical_view_types = sorted(
        {
            _normalize_string(item)
            for item in data.get("canonical_view_types", [])
            if _normalize_string(item)
        }
    )
    local_only_view_types = sorted(
        {
            _normalize_string(item)
            for item in data.get("local_only_view_types", [])
            if _normalize_string(item)
        }
    )
    builder_versions = {}
    raw_versions = data.get("builder_versions", {})
    if isinstance(raw_versions, dict):
        for key, value in raw_versions.items():
            key_str = _normalize_string(key)
            if not key_str:
                continue
            builder_versions[key_str] = _safe_int(value, default=1)
    return {
        "version": max(1, _safe_int(data.get("version", 1), default=1)),
        "canonical_view_types": canonical_view_types,
        "local_only_view_types": local_only_view_types,
        "builder_versions": dict(sorted(builder_versions.items())),
    }


def compute_event_hash(event: dict[str, Any]) -> str:
    body = dict(event)
    body.pop("integrity_hash", None)
    return _sha256_hex(body)


def compute_event_id(event: dict[str, Any]) -> str:
    return f"e:{compute_event_hash(event)}"


def compute_head_hash(event: dict[str, Any]) -> str:
    marker = {
        "event_id": _normalize_string(event.get("event_id", "")),
        "integrity_hash": _normalize_string(event.get("integrity_hash", "")),
        "prev_hash": _normalize_string(event.get("prev_hash", "")),
        "writer_id": _normalize_string(event.get("writer_id", "")),
    }
    return _sha256_hex(marker)


def compute_checkpoint_hash(checkpoint: dict[str, Any]) -> str:
    body = dict(checkpoint)
    body.pop("summary_hash", None)
    return _sha256_hex(body)


def compute_view_hash(view: dict[str, Any]) -> str:
    body = dict(view)
    body.pop("view_hash", None)
    return _sha256_hex(body)


def normalize_index0_event(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    modified_ts = _safe_int(raw.get("modified_ts", 0), default=0)
    if modified_ts <= 0:
        return None
    event = {
        "event_type": _normalize_string(raw.get("event_type", "")),
        "subject_type": _normalize_string(raw.get("subject_type", "")),
        "subject_id": _normalize_string(raw.get("subject_id", "")),
        "subject_kind": _normalize_string(raw.get("subject_kind", "")),
        "scope_path": _normalize_string(raw.get("scope_path", "")),
        "actor_type": _normalize_string(raw.get("actor_type", "")),
        "actor_id": _normalize_string(raw.get("actor_id", "")),
        "writer_id": _normalize_string(raw.get("writer_id", "")),
        "modified_ts": modified_ts,
        "prev_hash": _normalize_string(raw.get("prev_hash", "")),
        "classification": _normalize_string(raw.get("classification", "internal"))
        or "internal",
        "partition": _normalize_string(raw.get("partition", "standard")) or "standard",
        "payload_ref": _normalize_mapping(raw.get("payload_ref")),
        "links": _normalize_links(raw.get("links")),
        "tags": _normalize_tags(raw.get("tags")),
        "visibility": _normalize_string(raw.get("visibility", "private")) or "private",
    }
    for key in ("policy_ref", "source", "source_event_id", "summary"):
        value = _normalize_string(raw.get(key, ""))
        if value:
            event[key] = value
    required = (
        event["event_type"],
        event["subject_type"],
        event["subject_id"],
        event["writer_id"],
    )
    if not all(required):
        return None
    event["integrity_hash"] = _normalize_string(raw.get("integrity_hash", ""))
    expected_hash = compute_event_hash(event)
    if not event["integrity_hash"]:
        event["integrity_hash"] = expected_hash
    event["event_id"] = (
        _normalize_string(raw.get("event_id", "")) or f"e:{expected_hash}"
    )
    return event


def normalize_index0_checkpoint(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    checkpoint_id = _normalize_string(raw.get("checkpoint_id", ""))
    writer_id = _normalize_string(raw.get("writer_id", ""))
    window_type = _normalize_string(raw.get("window_type", ""))
    window_key = _normalize_string(raw.get("window_key", ""))
    modified_ts = _safe_int(raw.get("modified_ts", 0), default=0)
    if (
        not checkpoint_id
        or not writer_id
        or not window_type
        or not window_key
        or modified_ts <= 0
    ):
        return None
    rollup_raw = _normalize_mapping(raw.get("rollup"))
    events_by_type = _normalize_mapping(rollup_raw.get("events_by_type"))
    subjects_by_kind = _normalize_mapping(rollup_raw.get("subjects_by_kind"))
    subjects = _normalize_tags(rollup_raw.get("subjects"))
    checkpoint = {
        "checkpoint_id": checkpoint_id,
        "window_type": window_type,
        "window_key": window_key,
        "writer_id": writer_id,
        "window_start_ts": _safe_int(raw.get("window_start_ts", 0), default=0),
        "window_end_ts": _safe_int(raw.get("window_end_ts", 0), default=0),
        "event_count": max(0, _safe_int(raw.get("event_count", 0), default=0)),
        "head_hash": _normalize_string(raw.get("head_hash", "")),
        "rollup": {
            "events_by_type": {
                _normalize_string(k): _safe_int(v, default=0)
                for k, v in sorted(
                    events_by_type.items(), key=lambda item: str(item[0])
                )
                if _normalize_string(k)
            },
            "subjects_by_kind": {
                _normalize_string(k): _safe_int(v, default=0)
                for k, v in sorted(
                    subjects_by_kind.items(), key=lambda item: str(item[0])
                )
                if _normalize_string(k)
            },
            "subjects": subjects,
        },
        "modified_ts": modified_ts,
    }
    checkpoint["summary_hash"] = _normalize_string(
        raw.get("summary_hash", "")
    ) or compute_checkpoint_hash(checkpoint)
    return checkpoint


def normalize_canonical_view(
    raw: Any, *, view_manifest: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    view_type = _normalize_string(raw.get("view_type", ""))
    modified_ts = _safe_int(raw.get("modified_ts", 0), default=0)
    if not view_type or modified_ts <= 0:
        return None
    if view_type in LOCAL_ONLY_VIEW_TYPES:
        return None
    if view_manifest:
        local_only = set(view_manifest.get("local_only_view_types", []))
        if view_type in local_only:
            return None
    view = {
        "view_id": _normalize_string(raw.get("view_id", "")),
        "view_type": view_type,
        "scope_path": _normalize_string(raw.get("scope_path", "")),
        "source_checkpoint_ids": _normalize_tags(raw.get("source_checkpoint_ids")),
        "source_event_ids": _normalize_tags(raw.get("source_event_ids")),
        "data": _normalize_mapping(raw.get("data")),
        "modified_ts": modified_ts,
    }
    if not view["view_id"]:
        return None
    view["view_hash"] = _normalize_string(
        raw.get("view_hash", "")
    ) or compute_view_hash(view)
    return view


def normalize_head(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    event_id = _normalize_string(raw.get("event_id", ""))
    head_hash = _normalize_string(raw.get("head_hash", ""))
    modified_ts = _safe_int(raw.get("modified_ts", 0), default=0)
    if not event_id or not head_hash or modified_ts <= 0:
        return None
    return {"event_id": event_id, "head_hash": head_hash, "modified_ts": modified_ts}


def _prefer_hashed_record(
    current: dict[str, Any], incoming: dict[str, Any], *, hash_field: str
) -> bool:
    cur_ts = _safe_int(current.get("modified_ts", 0), default=0)
    inc_ts = _safe_int(incoming.get("modified_ts", 0), default=0)
    if inc_ts != cur_ts:
        return inc_ts > cur_ts
    return _normalize_string(incoming.get(hash_field, "")) > _normalize_string(
        current.get(hash_field, "")
    )


def merge_system_index0(current: Any, incoming: Any) -> dict[str, Any]:
    cur = normalize_index0(current)
    inc = normalize_index0(incoming)

    events = dict(cur["events"])
    for event_id, event in inc["events"].items():
        existing = events.get(event_id)
        if existing is None:
            events[event_id] = event
            continue
        if _canonical(existing) == _canonical(event):
            continue
        if _sha256_hex(event) > _sha256_hex(existing):
            events[event_id] = event

    checkpoints = dict(cur["checkpoints"])
    for checkpoint_id, checkpoint in inc["checkpoints"].items():
        existing = checkpoints.get(checkpoint_id)
        if existing is None:
            checkpoints[checkpoint_id] = checkpoint
            continue
        if _prefer_hashed_record(existing, checkpoint, hash_field="summary_hash"):
            checkpoints[checkpoint_id] = checkpoint

    view_manifest = normalize_view_manifest(
        {
            "version": max(
                _safe_int(cur["view_manifest"].get("version", 1), default=1),
                _safe_int(inc["view_manifest"].get("version", 1), default=1),
            ),
            "canonical_view_types": sorted(
                set(cur["view_manifest"].get("canonical_view_types", []))
                | set(inc["view_manifest"].get("canonical_view_types", []))
            ),
            "local_only_view_types": sorted(
                set(cur["view_manifest"].get("local_only_view_types", []))
                | set(inc["view_manifest"].get("local_only_view_types", []))
            ),
            "builder_versions": {
                **cur["view_manifest"].get("builder_versions", {}),
                **inc["view_manifest"].get("builder_versions", {}),
            },
        }
    )

    views = dict(cur["canonical_views"])
    for view_id, view in inc["canonical_views"].items():
        normalized_view = normalize_canonical_view(view, view_manifest=view_manifest)
        if normalized_view is None:
            continue
        existing = views.get(view_id)
        if existing is None:
            views[view_id] = normalized_view
            continue
        if _prefer_hashed_record(existing, normalized_view, hash_field="view_hash"):
            views[view_id] = normalized_view

    heads = dict(cur["heads"])
    for writer_id, head in inc["heads"].items():
        existing = heads.get(writer_id)
        if existing is None or _prefer_hashed_record(
            existing, head, hash_field="head_hash"
        ):
            heads[writer_id] = head

    merged = {
        "schema_version": max(cur["schema_version"], inc["schema_version"]),
        "events": dict(sorted(events.items())),
        "checkpoints": dict(sorted(checkpoints.items())),
        "canonical_views": dict(sorted(views.items())),
        "view_manifest": view_manifest,
        "heads": dict(sorted(heads.items())),
        "stats": {},
    }
    merged["stats"] = recompute_index0_stats(merged)
    return merged


def recompute_index0_stats(index0: dict[str, Any]) -> dict[str, Any]:
    events = _normalize_mapping(index0.get("events"))
    checkpoints = _normalize_mapping(index0.get("checkpoints"))
    heads = _normalize_mapping(index0.get("heads"))
    stats = {
        "event_count": len(events),
        "checkpoint_count": len(checkpoints),
        "writer_count": len(heads),
        "last_compaction_ts": 0,
        "last_validation_ts": 0,
    }
    checkpoint_ts = [
        _safe_int(value.get("modified_ts", 0), default=0)
        for value in checkpoints.values()
        if isinstance(value, dict)
    ]
    head_ts = [
        _safe_int(value.get("modified_ts", 0), default=0)
        for value in heads.values()
        if isinstance(value, dict)
    ]
    if checkpoint_ts:
        stats["last_compaction_ts"] = max(checkpoint_ts)
    if head_ts:
        stats["last_validation_ts"] = max(head_ts)
    return stats
