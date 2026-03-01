from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR

IDENTITY_STORE_VERSION = 1


def _store_path() -> Path:
    return APP_DIR / "agent_identities.json"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_store() -> dict[str, Any]:
    return {"version": IDENTITY_STORE_VERSION, "identities": []}


def _load_store() -> dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return _empty_store()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("identities"), list):
        return _empty_store()
    return data


def _save_store(store: dict[str, Any]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def list_identities(*, include_revoked: bool = False) -> list[dict[str, Any]]:
    identities = _load_store().get("identities", [])
    if include_revoked:
        return identities
    return [v for v in identities if not v.get("revoked_at_utc")]


def get_identity(identity_id: str) -> dict[str, Any] | None:
    target = str(identity_id).strip()
    if not target:
        return None
    for rec in _load_store().get("identities", []):
        if str(rec.get("id", "")) == target:
            return rec
    return None


def create_identity(
    *,
    identity_id: str,
    owner: str,
    policy_binding: str = "default",
    rotation_days: int = 30,
) -> dict[str, Any]:
    identity_id = str(identity_id).strip()
    if not identity_id:
        raise ValueError("identity_id_required")
    if get_identity(identity_id):
        raise ValueError("identity_exists")

    rec = {
        "id": identity_id,
        "owner": str(owner).strip() or "unowned",
        "policy_binding": str(policy_binding).strip() or "default",
        "rotation_days": int(rotation_days),
        "created_at_utc": _utcnow_iso(),
        "revoked_at_utc": None,
    }
    store = _load_store()
    store.setdefault("version", IDENTITY_STORE_VERSION)
    store.setdefault("identities", [])
    store["identities"].append(rec)
    _save_store(store)
    return rec


def ensure_identity(
    identity_id: str,
    *,
    owner: str = "system",
    policy_binding: str = "default",
    rotation_days: int = 30,
) -> dict[str, Any]:
    existing = get_identity(identity_id)
    if existing:
        return existing
    return create_identity(
        identity_id=identity_id,
        owner=owner,
        policy_binding=policy_binding,
        rotation_days=rotation_days,
    )


def revoke_identity(identity_id: str) -> bool:
    identity_id = str(identity_id).strip()
    if not identity_id:
        return False
    store = _load_store()
    changed = False
    now = _utcnow_iso()
    for rec in store.get("identities", []):
        if str(rec.get("id", "")) == identity_id and not rec.get("revoked_at_utc"):
            rec["revoked_at_utc"] = now
            changed = True
            break
    if changed:
        _save_store(store)
    return changed


def identity_active(identity_id: str) -> bool:
    rec = get_identity(identity_id)
    if not rec:
        return False
    return not bool(rec.get("revoked_at_utc"))
