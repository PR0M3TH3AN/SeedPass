from __future__ import annotations

"""Service layer wrapping :class:`PasswordManager` operations.

These services provide thread-safe methods for common operations used by the CLI
and API. Request and response payloads are represented using Pydantic models to
allow easy validation and documentation.
"""

from pathlib import Path
from threading import Lock
from typing import List, Optional, Dict

from pydantic import BaseModel

from .manager import PasswordManager


class VaultExportRequest(BaseModel):
    """Parameters required to export the vault."""

    path: Path


class VaultExportResponse(BaseModel):
    """Result of a vault export operation."""

    path: Path


class VaultImportRequest(BaseModel):
    """Parameters required to import a vault."""

    path: Path


class ChangePasswordRequest(BaseModel):
    """Payload for :meth:`VaultService.change_password`."""

    old_password: str
    new_password: str


class UnlockRequest(BaseModel):
    """Payload for unlocking the vault."""

    password: str


class UnlockResponse(BaseModel):
    """Duration taken to unlock the vault."""

    duration: float


class BackupParentSeedRequest(BaseModel):
    """Optional path to write the encrypted seed backup."""

    path: Optional[Path] = None


class ProfileSwitchRequest(BaseModel):
    """Select a different seed profile."""

    fingerprint: str


class ProfileRemoveRequest(BaseModel):
    """Remove a seed profile."""

    fingerprint: str


class SyncResponse(BaseModel):
    """Information about uploaded events after syncing."""

    manifest_id: str
    chunk_ids: List[str] = []
    delta_ids: List[str] = []


class VaultService:
    """Thread-safe wrapper around vault operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def export_vault(self, req: VaultExportRequest) -> VaultExportResponse:
        """Export the vault to ``req.path``."""

        with self._lock:
            self._manager.handle_export_database(req.path)
        return VaultExportResponse(path=req.path)

    def import_vault(self, req: VaultImportRequest) -> None:
        """Import the vault from ``req.path`` and sync."""

        with self._lock:
            self._manager.handle_import_database(req.path)
            self._manager.sync_vault()

    def change_password(self, req: ChangePasswordRequest) -> None:
        """Change the master password."""

        with self._lock:
            self._manager.change_password(req.old_password, req.new_password)

    def unlock(self, req: UnlockRequest) -> UnlockResponse:
        """Unlock the vault and return the duration."""

        with self._lock:
            duration = self._manager.unlock_vault(req.password)
        return UnlockResponse(duration=duration)

    def lock(self) -> None:
        """Lock the vault and clear sensitive data."""

        with self._lock:
            self._manager.lock_vault()

    def backup_parent_seed(self, req: BackupParentSeedRequest) -> None:
        """Backup and reveal the parent seed."""

        with self._lock:
            self._manager.handle_backup_reveal_parent_seed(req.path)

    def stats(self) -> Dict:
        """Return statistics about the current profile."""

        with self._lock:
            return self._manager.get_profile_stats()


class ProfileService:
    """Thread-safe wrapper around profile management operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def list_profiles(self) -> List[str]:
        """List available seed profiles."""

        with self._lock:
            return list(self._manager.fingerprint_manager.list_fingerprints())

    def add_profile(self) -> Optional[str]:
        """Create a new seed profile and return its fingerprint if available."""

        with self._lock:
            self._manager.add_new_fingerprint()
            return getattr(
                self._manager.fingerprint_manager, "current_fingerprint", None
            )

    def remove_profile(self, req: ProfileRemoveRequest) -> None:
        """Remove the specified seed profile."""

        with self._lock:
            self._manager.fingerprint_manager.remove_fingerprint(req.fingerprint)

    def switch_profile(self, req: ProfileSwitchRequest) -> None:
        """Switch to ``req.fingerprint``."""

        with self._lock:
            self._manager.select_fingerprint(req.fingerprint)


class SyncService:
    """Thread-safe wrapper around vault synchronization."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def sync(self) -> Optional[SyncResponse]:
        """Publish the vault to Nostr and return event info."""

        with self._lock:
            result = self._manager.sync_vault()
        if not result:
            return None
        return SyncResponse(**result)

    def start_background_sync(self) -> None:
        """Begin background synchronization if possible."""

        with self._lock:
            self._manager.start_background_sync()

    def start_background_vault_sync(self, summary: Optional[str] = None) -> None:
        """Publish the vault in a background thread."""

        with self._lock:
            self._manager.start_background_vault_sync(summary)
