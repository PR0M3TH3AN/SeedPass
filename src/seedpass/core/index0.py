from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INDEX0_SCHEMA_VERSION = 1
LOCAL_ONLY_VIEW_TYPES = {"hot_nodes", "conversation_index", "semantic_neighbors"}
INDEX0_CHECKPOINT_SUBJECT_CAP = 64
INDEX0_MAX_CHECKPOINTS_PER_WRITER = 30
INDEX0_MANIFEST_CHECKPOINT_LIMIT = 32
INDEX0_RECENT_ACTIVITY_LIMIT = 20
INDEX0_CANONICAL_VIEW_TYPES = ("children_of", "counts_by_kind", "recent_activity")


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


def derive_index0_context(
    fingerprint_dir: str | Path,
    *,
    actor_type: str = "user",
) -> dict[str, str]:
    path = Path(fingerprint_dir)
    current_fp = path.name.strip()
    parent = path.parent
    if parent.name == "accounts":
        root_fp = parent.parent.name.strip()
        scope_path = f"seed/{root_fp}/managed/{current_fp}"
    else:
        root_fp = current_fp
        scope_path = f"seed/{current_fp}"
    return {
        "actor_type": _normalize_string(actor_type) or "user",
        "actor_id": current_fp,
        "writer_id": f"writer:profile:{current_fp}",
        "scope_path": scope_path,
        "root_fingerprint": root_fp,
        "current_fingerprint": current_fp,
    }


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


def _window_key_for_ts(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def _event_sort_key(event: dict[str, Any]) -> tuple[int, str]:
    return (
        _safe_int(event.get("modified_ts", 0), default=0),
        _normalize_string(event.get("event_id", "")),
    )


def make_index0_event(
    *,
    event_type: str,
    subject_type: str,
    subject_id: Any,
    subject_kind: str,
    modified_ts: int,
    writer_id: str,
    actor_id: str,
    scope_path: str,
    actor_type: str = "user",
    payload_ref: dict[str, Any] | None = None,
    links: list[dict[str, Any]] | None = None,
    tags: list[str] | None = None,
    prev_hash: str = "",
    classification: str = "internal",
    partition: str = "standard",
    visibility: str = "private",
    policy_ref: str = "",
    source: str = "",
    source_event_id: str = "",
    summary: str = "",
) -> dict[str, Any]:
    event = {
        "event_type": _normalize_string(event_type),
        "subject_type": _normalize_string(subject_type),
        "subject_id": _normalize_string(subject_id),
        "subject_kind": _normalize_string(subject_kind),
        "scope_path": _normalize_string(scope_path),
        "actor_type": _normalize_string(actor_type) or "user",
        "actor_id": _normalize_string(actor_id),
        "writer_id": _normalize_string(writer_id),
        "modified_ts": max(1, _safe_int(modified_ts, default=1)),
        "prev_hash": _normalize_string(prev_hash),
        "classification": _normalize_string(classification) or "internal",
        "partition": _normalize_string(partition) or "standard",
        "payload_ref": _normalize_mapping(payload_ref),
        "links": _normalize_links(links),
        "tags": _normalize_tags(tags),
        "visibility": _normalize_string(visibility) or "private",
    }
    for key, value in {
        "policy_ref": policy_ref,
        "source": source,
        "source_event_id": source_event_id,
        "summary": summary,
    }.items():
        normalized = _normalize_string(value)
        if normalized:
            event[key] = normalized
    event["integrity_hash"] = compute_event_hash(event)
    event["event_id"] = compute_event_id(event)
    return normalize_index0_event(event) or event


def append_index0_event(
    payload: dict[str, Any],
    *,
    event_type: str,
    subject_type: str,
    subject_id: Any,
    subject_kind: str,
    modified_ts: int,
    fingerprint_dir: str | Path,
    actor_type: str = "user",
    payload_ref: dict[str, Any] | None = None,
    links: list[dict[str, Any]] | None = None,
    tags: list[str] | None = None,
    classification: str = "internal",
    partition: str = "standard",
    visibility: str = "private",
    policy_ref: str = "",
    source: str = "",
    source_event_id: str = "",
    summary: str = "",
) -> dict[str, Any]:
    out = ensure_index0_payload(payload)
    system_index0 = out["_system"]["index0"]
    context = derive_index0_context(fingerprint_dir, actor_type=actor_type)
    head = system_index0.get("heads", {}).get(context["writer_id"], {})
    prev_hash = ""
    if isinstance(head, dict):
        prev_hash = _normalize_string(head.get("head_hash", ""))
    event = make_index0_event(
        event_type=event_type,
        subject_type=subject_type,
        subject_id=subject_id,
        subject_kind=subject_kind,
        modified_ts=modified_ts,
        writer_id=context["writer_id"],
        actor_id=context["actor_id"],
        scope_path=context["scope_path"],
        actor_type=context["actor_type"],
        payload_ref=payload_ref,
        links=links,
        tags=tags,
        prev_hash=prev_hash,
        classification=classification,
        partition=partition,
        visibility=visibility,
        policy_ref=policy_ref,
        source=source,
        source_event_id=source_event_id,
        summary=summary,
    )
    system_index0["events"][event["event_id"]] = event
    system_index0["heads"][context["writer_id"]] = {
        "event_id": event["event_id"],
        "head_hash": compute_head_hash(event),
        "modified_ts": event["modified_ts"],
    }
    system_index0["stats"] = recompute_index0_stats(system_index0)
    return out


def build_daily_checkpoint(
    writer_id: str,
    window_key: str,
    events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    ordered = sorted(
        [
            normalize_index0_event(event)
            for event in events
            if isinstance(event, dict) and normalize_index0_event(event) is not None
        ],
        key=_event_sort_key,
    )
    if not ordered:
        return None
    latest = ordered[-1]
    events_by_type: dict[str, int] = {}
    subjects_by_kind: dict[str, int] = {}
    subjects = sorted(
        {
            _normalize_string(event.get("subject_id", ""))
            for event in ordered
            if _normalize_string(event.get("subject_id", ""))
        }
    )[:INDEX0_CHECKPOINT_SUBJECT_CAP]
    for event in ordered:
        event_type = _normalize_string(event.get("event_type", ""))
        subject_kind = _normalize_string(event.get("subject_kind", ""))
        if event_type:
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
        if subject_kind:
            subjects_by_kind[subject_kind] = subjects_by_kind.get(subject_kind, 0) + 1
    checkpoint = {
        "checkpoint_id": f"cp:day:{window_key}:{writer_id}",
        "window_type": "day",
        "window_key": window_key,
        "writer_id": writer_id,
        "window_start_ts": _safe_int(ordered[0].get("modified_ts", 0), default=0),
        "window_end_ts": _safe_int(latest.get("modified_ts", 0), default=0),
        "event_count": len(ordered),
        "head_hash": compute_head_hash(latest),
        "rollup": {
            "events_by_type": dict(sorted(events_by_type.items())),
            "subjects_by_kind": dict(sorted(subjects_by_kind.items())),
            "subjects": subjects,
        },
        "modified_ts": _safe_int(latest.get("modified_ts", 0), default=0),
    }
    checkpoint["summary_hash"] = compute_checkpoint_hash(checkpoint)
    return normalize_index0_checkpoint(checkpoint)


def rebuild_index0_checkpoints(
    index0: dict[str, Any],
    *,
    max_checkpoints_per_writer: int = INDEX0_MAX_CHECKPOINTS_PER_WRITER,
) -> dict[str, dict[str, Any]]:
    events = _normalize_mapping(index0.get("events"))
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in events.values():
        normalized = normalize_index0_event(event)
        if normalized is None:
            continue
        writer_id = _normalize_string(normalized.get("writer_id", ""))
        if not writer_id:
            continue
        window_key = _window_key_for_ts(
            _safe_int(normalized.get("modified_ts", 0), default=0)
        )
        grouped.setdefault((writer_id, window_key), []).append(normalized)

    checkpoints: dict[str, dict[str, Any]] = {}
    windows_by_writer: dict[str, list[str]] = {}
    for (writer_id, window_key), writer_events in grouped.items():
        checkpoint = build_daily_checkpoint(writer_id, window_key, writer_events)
        if checkpoint is None:
            continue
        checkpoints[checkpoint["checkpoint_id"]] = checkpoint
        windows_by_writer.setdefault(writer_id, []).append(window_key)

    retained_ids: set[str] = set()
    for writer_id, window_keys in windows_by_writer.items():
        keep = sorted(set(window_keys), reverse=True)[
            : max(1, max_checkpoints_per_writer)
        ]
        for window_key in keep:
            retained_ids.add(f"cp:day:{window_key}:{writer_id}")
    return {
        checkpoint_id: checkpoints[checkpoint_id]
        for checkpoint_id in sorted(retained_ids)
        if checkpoint_id in checkpoints
    }


def compact_index0(
    index0: dict[str, Any],
    *,
    max_checkpoints_per_writer: int = INDEX0_MAX_CHECKPOINTS_PER_WRITER,
) -> dict[str, Any]:
    normalized = normalize_index0(index0)
    normalized["checkpoints"] = rebuild_index0_checkpoints(
        normalized, max_checkpoints_per_writer=max_checkpoints_per_writer
    )
    normalized["stats"] = recompute_index0_stats(normalized)
    return normalized


def _normalize_entry_summary(entry_id: str, entry: dict[str, Any]) -> dict[str, Any]:
    kind = (
        _normalize_string(entry.get("kind", entry.get("type", "password")))
        or "password"
    )
    label = _normalize_string(entry.get("label", entry.get("website", "")))
    return {
        "entry_id": _normalize_string(entry_id),
        "kind": kind,
        "label": label,
        "archived": bool(entry.get("archived", entry.get("blacklisted", False))),
        "modified_ts": _safe_int(
            entry.get("modified_ts", entry.get("updated", 0)), default=0
        ),
        "link_count": len(_normalize_links(entry.get("links", []))),
        "tag_count": len(_normalize_tags(entry.get("tags", []))),
    }


def _build_children_view(
    scope_path: str,
    entries: dict[str, Any],
    event_ids: list[str],
    checkpoint_ids: list[str],
) -> dict[str, Any]:
    items = [
        _normalize_entry_summary(entry_id, entry)
        for entry_id, entry in sorted(
            _normalize_mapping(entries).items(), key=lambda item: int(str(item[0]))
        )
        if isinstance(entry, dict)
    ]
    modified_ts = max(
        [item["modified_ts"] for item in items if item["modified_ts"] > 0] or [0]
    )
    return {
        "view_id": f"children_of:{scope_path}",
        "view_type": "children_of",
        "scope_path": scope_path,
        "source_checkpoint_ids": checkpoint_ids,
        "source_event_ids": event_ids,
        "data": {
            "children": items,
            "total_children": len(items),
        },
        "modified_ts": max(1, modified_ts),
    }


def _build_counts_view(
    scope_path: str,
    entries: dict[str, Any],
    event_ids: list[str],
    checkpoint_ids: list[str],
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    archived_count = 0
    for entry in _normalize_mapping(entries).values():
        if not isinstance(entry, dict):
            continue
        kind = _normalize_string(entry.get("kind", entry.get("type", "password")))
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
        if bool(entry.get("archived", entry.get("blacklisted", False))):
            archived_count += 1
    modified_ts = max(
        [
            _safe_int(entry.get("modified_ts", entry.get("updated", 0)), default=0)
            for entry in _normalize_mapping(entries).values()
            if isinstance(entry, dict)
        ]
        or [0]
    )
    return {
        "view_id": f"counts_by_kind:{scope_path}",
        "view_type": "counts_by_kind",
        "scope_path": scope_path,
        "source_checkpoint_ids": checkpoint_ids,
        "source_event_ids": event_ids,
        "data": {
            "counts": dict(sorted(counts.items())),
            "archived_count": archived_count,
            "total_entries": sum(counts.values()),
        },
        "modified_ts": max(1, modified_ts),
    }


def _build_recent_activity_view(
    scope_path: str,
    events: list[dict[str, Any]],
    checkpoint_ids: list[str],
) -> dict[str, Any]:
    ordered = sorted(events, key=_event_sort_key, reverse=True)[
        :INDEX0_RECENT_ACTIVITY_LIMIT
    ]
    items = [
        {
            "event_id": _normalize_string(event.get("event_id", "")),
            "event_type": _normalize_string(event.get("event_type", "")),
            "subject_id": _normalize_string(event.get("subject_id", "")),
            "subject_kind": _normalize_string(event.get("subject_kind", "")),
            "modified_ts": _safe_int(event.get("modified_ts", 0), default=0),
            "summary": _normalize_string(event.get("summary", "")),
        }
        for event in ordered
    ]
    modified_ts = max(
        [item["modified_ts"] for item in items if item["modified_ts"] > 0] or [0]
    )
    return {
        "view_id": f"recent_activity:{scope_path}",
        "view_type": "recent_activity",
        "scope_path": scope_path,
        "source_checkpoint_ids": checkpoint_ids,
        "source_event_ids": [item["event_id"] for item in items if item["event_id"]],
        "data": {
            "items": items,
            "total_items": len(items),
        },
        "modified_ts": max(1, modified_ts),
    }


def rebuild_canonical_views_payload(
    payload: dict[str, Any],
    *,
    fingerprint_dir: str | Path | None = None,
) -> dict[str, Any]:
    out = ensure_index0_payload(payload)
    index0 = out["_system"]["index0"]
    entries = _normalize_mapping(out.get("entries"))
    events = [
        normalize_index0_event(event)
        for event in index0.get("events", {}).values()
        if normalize_index0_event(event) is not None
    ]
    checkpoints = _normalize_mapping(index0.get("checkpoints"))

    scope_paths = {
        _normalize_string(event.get("scope_path", ""))
        for event in events
        if _normalize_string(event.get("scope_path", ""))
    }
    if fingerprint_dir is not None:
        scope_paths.add(derive_index0_context(fingerprint_dir)["scope_path"])
    scope_paths = {scope for scope in scope_paths if scope}

    views: dict[str, Any] = {}
    for scope_path in sorted(scope_paths):
        scope_events = [
            event
            for event in events
            if _normalize_string(event.get("scope_path", "")) == scope_path
        ]
        checkpoint_ids = sorted(
            {
                checkpoint_id
                for checkpoint_id, checkpoint in checkpoints.items()
                if isinstance(checkpoint, dict)
                and any(
                    _normalize_string(event.get("writer_id", ""))
                    == _normalize_string(checkpoint.get("writer_id", ""))
                    for event in scope_events
                )
            }
        )
        source_event_ids = sorted(
            {
                _normalize_string(event.get("event_id", ""))
                for event in scope_events
                if _normalize_string(event.get("event_id", ""))
            }
        )
        for raw_view in (
            _build_children_view(scope_path, entries, source_event_ids, checkpoint_ids),
            _build_counts_view(scope_path, entries, source_event_ids, checkpoint_ids),
            _build_recent_activity_view(scope_path, scope_events, checkpoint_ids),
        ):
            raw_view["view_hash"] = compute_view_hash(raw_view)
            normalized_view = normalize_canonical_view(
                raw_view,
                view_manifest={
                    "local_only_view_types": sorted(LOCAL_ONLY_VIEW_TYPES),
                },
            )
            if normalized_view is not None:
                views[normalized_view["view_id"]] = normalized_view

    index0["view_manifest"] = normalize_view_manifest(
        {
            "version": 1,
            "canonical_view_types": list(INDEX0_CANONICAL_VIEW_TYPES),
            "local_only_view_types": sorted(LOCAL_ONLY_VIEW_TYPES),
            "builder_versions": {
                view_type: 1 for view_type in INDEX0_CANONICAL_VIEW_TYPES
            },
        }
    )
    index0["canonical_views"] = dict(sorted(views.items()))
    index0["stats"] = recompute_index0_stats(index0)
    out["_system"]["index0"] = index0
    return out


def compact_index0_payload(
    payload: dict[str, Any],
    *,
    max_checkpoints_per_writer: int = INDEX0_MAX_CHECKPOINTS_PER_WRITER,
    fingerprint_dir: str | Path | None = None,
) -> dict[str, Any]:
    out = ensure_index0_payload(payload)
    out["_system"]["index0"] = compact_index0(
        out["_system"]["index0"],
        max_checkpoints_per_writer=max_checkpoints_per_writer,
    )
    return rebuild_canonical_views_payload(out, fingerprint_dir=fingerprint_dir)


def build_manifest_index0_metadata(
    payload: dict[str, Any],
    *,
    checkpoint_limit: int = INDEX0_MANIFEST_CHECKPOINT_LIMIT,
    fingerprint_dir: str | Path | None = None,
) -> dict[str, Any]:
    compacted = compact_index0_payload(payload, fingerprint_dir=fingerprint_dir)
    index0 = compacted["_system"]["index0"]
    checkpoints = [
        checkpoint
        for checkpoint in index0.get("checkpoints", {}).values()
        if isinstance(checkpoint, dict)
    ]
    selected = sorted(
        checkpoints,
        key=lambda checkpoint: (
            _safe_int(checkpoint.get("modified_ts", 0), default=0),
            _normalize_string(checkpoint.get("checkpoint_id", "")),
        ),
        reverse=True,
    )[: max(0, checkpoint_limit)]
    checkpoint_ids = [
        _normalize_string(checkpoint.get("checkpoint_id", ""))
        for checkpoint in selected
        if _normalize_string(checkpoint.get("checkpoint_id", ""))
    ]
    return {
        "schema_version": INDEX0_SCHEMA_VERSION,
        "checkpoint_ids": checkpoint_ids,
        "checkpoint_hashes": {
            checkpoint_id: _normalize_string(
                index0["checkpoints"][checkpoint_id].get("summary_hash", "")
            )
            for checkpoint_id in checkpoint_ids
            if checkpoint_id in index0.get("checkpoints", {})
        },
        "stream_heads": {
            writer_id: _normalize_string(head.get("head_hash", ""))
            for writer_id, head in sorted(
                _normalize_mapping(index0.get("heads")).items()
            )
            if isinstance(head, dict) and _normalize_string(head.get("head_hash", ""))
        },
    }


def list_canonical_views(index0: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = normalize_index0(index0)
    return [
        normalized["canonical_views"][key]
        for key in sorted(normalized["canonical_views"])
    ]


def get_canonical_view(
    index0: dict[str, Any], *, view_type: str, scope_path: str
) -> dict[str, Any] | None:
    normalized = normalize_index0(index0)
    view_id = f"{_normalize_string(view_type)}:{_normalize_string(scope_path)}"
    view = normalized["canonical_views"].get(view_id)
    return dict(view) if isinstance(view, dict) else None


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
