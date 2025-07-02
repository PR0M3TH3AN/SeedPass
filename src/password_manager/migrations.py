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


LATEST_VERSION = 1


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
