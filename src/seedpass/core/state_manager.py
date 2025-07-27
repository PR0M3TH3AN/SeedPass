from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from utils.file_lock import exclusive_lock, shared_lock
from nostr.client import DEFAULT_RELAYS


class StateManager:
    """Persist simple state values per profile."""

    STATE_FILENAME = "seedpass_state.json"

    def __init__(self, fingerprint_dir: Path) -> None:
        self.fingerprint_dir = Path(fingerprint_dir)
        self.state_path = self.fingerprint_dir / self.STATE_FILENAME

    def _load(self) -> dict:
        if not self.state_path.exists():
            return {
                "last_bip85_idx": 0,
                "last_sync_ts": 0,
                "manifest_id": None,
                "delta_since": 0,
                "relays": list(DEFAULT_RELAYS),
            }
        with shared_lock(self.state_path) as fh:
            fh.seek(0)
            data = fh.read()
        if not data:
            return {
                "last_bip85_idx": 0,
                "last_sync_ts": 0,
                "manifest_id": None,
                "delta_since": 0,
                "relays": list(DEFAULT_RELAYS),
            }
        try:
            obj = json.loads(data.decode())
        except Exception:
            obj = {}
        obj.setdefault("last_bip85_idx", 0)
        obj.setdefault("last_sync_ts", 0)
        obj.setdefault("manifest_id", None)
        obj.setdefault("delta_since", 0)
        obj.setdefault("relays", list(DEFAULT_RELAYS))
        return obj

    def _save(self, data: dict) -> None:
        with exclusive_lock(self.state_path) as fh:
            fh.seek(0)
            fh.truncate()
            fh.write(json.dumps(data, separators=(",", ":")).encode())
            fh.flush()
            os.fsync(fh.fileno())

    @property
    def state(self) -> dict:
        return self._load()

    def update_state(self, **kwargs) -> None:
        data = self._load()
        data.update(kwargs)
        self._save(data)

    # Relay helpers
    def list_relays(self) -> List[str]:
        return self._load().get("relays", [])

    def add_relay(self, url: str) -> None:
        data = self._load()
        relays = data.get("relays", [])
        if url in relays:
            raise ValueError("Relay already present")
        relays.append(url)
        data["relays"] = relays
        self._save(data)

    def remove_relay(self, idx: int) -> None:
        data = self._load()
        relays = data.get("relays", [])
        if not 1 <= idx <= len(relays):
            raise ValueError("Invalid index")
        if len(relays) == 1:
            raise ValueError("At least one relay required")
        relays.pop(idx - 1)
        data["relays"] = relays
        self._save(data)
