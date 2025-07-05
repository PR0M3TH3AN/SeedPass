"""Schema migration helpers for password index files."""

from __future__ import annotations

from typing import Callable, Dict

MIGRATIONS: Dict[int, Callable[[dict], dict]] = {}


def migration(
    from_ver: int,
) -> Callable[[Callable[[dict], dict]], Callable[[dict], dict]]:
    """Register a migration function from *from_ver* to *from_ver* + 1."""

    def decorator(func: Callable[[dict], dict]) -> Callable[[dict], dict]:
        MIGRATIONS[from_ver] = func
        return func

    return decorator


@migration(0)
def _v0_to_v1(data: dict) -> dict:
    """Inject schema_version field for initial upgrade."""
    data["schema_version"] = 1
    return data


@migration(1)
def _v1_to_v2(data: dict) -> dict:
    passwords = data.pop("passwords", {})
    entries = {}
    for k, v in passwords.items():
        v.setdefault("type", "password")
        v.setdefault("notes", "")
        if "label" not in v and "website" in v:
            v["label"] = v["website"]
        if v.get("type") == "password" and "website" in v:
            v.pop("website", None)
        entries[k] = v
    data["entries"] = entries
    data["schema_version"] = 2
    return data


@migration(2)
def _v2_to_v3(data: dict) -> dict:
    """Add custom_fields and origin defaults to each entry."""
    entries = data.get("entries", {})
    for entry in entries.values():
        entry.setdefault("custom_fields", [])
        entry.setdefault("origin", "")
        if entry.get("type", "password") == "password":
            if "label" not in entry and "website" in entry:
                entry["label"] = entry["website"]
            entry.pop("website", None)
    data["schema_version"] = 3
    return data


LATEST_VERSION = 3


def apply_migrations(data: dict) -> dict:
    """Upgrade *data* in-place to the latest schema version."""
    current = data.get("schema_version", 0)
    if current > LATEST_VERSION:
        raise ValueError(f"Unsupported schema version {current}")

    while current < LATEST_VERSION:
        migrate = MIGRATIONS.get(current)
        if migrate is None:
            raise ValueError(f"No migration available from version {current}")
        data = migrate(data)
        current = data.get("schema_version", current + 1)

    return data
