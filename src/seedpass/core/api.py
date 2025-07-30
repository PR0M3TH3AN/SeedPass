from __future__ import annotations

"""Service layer wrapping :class:`PasswordManager` operations.

These services provide thread-safe methods for common operations used by the CLI
and API. Request and response payloads are represented using Pydantic models to
allow easy validation and documentation.
"""

from pathlib import Path
from threading import Lock
from typing import List, Optional, Dict
import json

from pydantic import BaseModel

from .manager import PasswordManager
from .pubsub import bus


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
    password: Optional[str] = None


class ProfileSwitchRequest(BaseModel):
    """Select a different seed profile."""

    fingerprint: str
    password: Optional[str] = None


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

    def export_profile(self) -> bytes:
        """Return encrypted profile data for backup."""

        with self._lock:
            data = self._manager.vault.load_index()
            payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            return self._manager.vault.encryption_manager.encrypt_data(payload)

    def import_profile(self, data: bytes) -> None:
        """Restore a profile from ``data`` and sync."""

        with self._lock:
            decrypted = self._manager.vault.encryption_manager.decrypt_data(data)
            index = json.loads(decrypted.decode("utf-8"))
            self._manager.vault.save_index(index)
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
            self._manager.handle_backup_reveal_parent_seed(
                req.path, password=req.password
            )

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
            self._manager.select_fingerprint(req.fingerprint, password=req.password)


class SyncService:
    """Thread-safe wrapper around vault synchronization."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def sync(self) -> Optional[SyncResponse]:
        """Publish the vault to Nostr and return event info."""

        with self._lock:
            bus.publish("sync_started")
            result = self._manager.sync_vault()
            bus.publish("sync_finished", result)
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


class EntryService:
    """Thread-safe wrapper around entry operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def list_entries(
        self,
        sort_by: str = "index",
        filter_kind: str | None = None,
        include_archived: bool = False,
    ):
        with self._lock:
            return self._manager.entry_manager.list_entries(
                sort_by=sort_by,
                filter_kind=filter_kind,
                include_archived=include_archived,
            )

    def search_entries(
        self, query: str, kinds: list[str] | None = None
    ) -> list[tuple[int, str, str | None, str | None, bool]]:
        """Search entries optionally filtering by ``kinds``.

        Parameters
        ----------
        query:
            Search string to match against entry metadata.
        kinds:
            Optional list of entry kinds to restrict the search.
        """

        with self._lock:
            return self._manager.entry_manager.search_entries(query, kinds=kinds)

    def retrieve_entry(self, entry_id: int):
        with self._lock:
            return self._manager.entry_manager.retrieve_entry(entry_id)

    def generate_password(self, length: int, index: int) -> str:
        with self._lock:
            return self._manager.password_generator.generate_password(length, index)

    def get_totp_code(self, entry_id: int) -> str:
        with self._lock:
            return self._manager.entry_manager.get_totp_code(
                entry_id, self._manager.parent_seed
            )

    def add_entry(
        self,
        label: str,
        length: int,
        username: str | None = None,
        url: str | None = None,
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_entry(label, length, username, url)
            self._manager.start_background_vault_sync()
            return idx

    def add_totp(
        self,
        label: str,
        *,
        index: int | None = None,
        secret: str | None = None,
        period: int = 30,
        digits: int = 6,
    ) -> str:
        with self._lock:
            uri = self._manager.entry_manager.add_totp(
                label,
                self._manager.parent_seed,
                index=index,
                secret=secret,
                period=period,
                digits=digits,
            )
            self._manager.start_background_vault_sync()
            return uri

    def add_ssh_key(
        self,
        label: str,
        *,
        index: int | None = None,
        notes: str = "",
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_ssh_key(
                label,
                self._manager.parent_seed,
                index=index,
                notes=notes,
            )
            self._manager.start_background_vault_sync()
            return idx

    def add_pgp_key(
        self,
        label: str,
        *,
        index: int | None = None,
        key_type: str = "ed25519",
        user_id: str = "",
        notes: str = "",
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_pgp_key(
                label,
                self._manager.parent_seed,
                index=index,
                key_type=key_type,
                user_id=user_id,
                notes=notes,
            )
            self._manager.start_background_vault_sync()
            return idx

    def add_nostr_key(
        self,
        label: str,
        *,
        index: int | None = None,
        notes: str = "",
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_nostr_key(
                label,
                index=index,
                notes=notes,
            )
            self._manager.start_background_vault_sync()
            return idx

    def add_seed(
        self,
        label: str,
        *,
        index: int | None = None,
        words: int = 24,
        notes: str = "",
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_seed(
                label,
                self._manager.parent_seed,
                index=index,
                words_num=words,
                notes=notes,
            )
            self._manager.start_background_vault_sync()
            return idx

    def add_key_value(
        self, label: str, key: str, value: str, *, notes: str = ""
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_key_value(
                label, key, value, notes=notes
            )
            self._manager.start_background_vault_sync()
            return idx

    def add_managed_account(
        self,
        label: str,
        *,
        index: int | None = None,
        notes: str = "",
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_managed_account(
                label,
                self._manager.parent_seed,
                index=index,
                notes=notes,
            )
            self._manager.start_background_vault_sync()
            return idx

    def modify_entry(
        self,
        entry_id: int,
        *,
        username: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        label: str | None = None,
        period: int | None = None,
        digits: int | None = None,
        key: str | None = None,
        value: str | None = None,
    ) -> None:
        with self._lock:
            self._manager.entry_manager.modify_entry(
                entry_id,
                username=username,
                url=url,
                notes=notes,
                label=label,
                period=period,
                digits=digits,
                key=key,
                value=value,
            )
            self._manager.start_background_vault_sync()

    def archive_entry(self, entry_id: int) -> None:
        with self._lock:
            self._manager.entry_manager.archive_entry(entry_id)
            self._manager.start_background_vault_sync()

    def restore_entry(self, entry_id: int) -> None:
        with self._lock:
            self._manager.entry_manager.restore_entry(entry_id)
            self._manager.start_background_vault_sync()

    def export_totp_entries(self) -> dict:
        with self._lock:
            return self._manager.entry_manager.export_totp_entries(
                self._manager.parent_seed
            )

    def display_totp_codes(self) -> None:
        with self._lock:
            self._manager.handle_display_totp_codes()


class ConfigService:
    """Thread-safe wrapper around configuration access."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def get(self, key: str):
        with self._lock:
            return self._manager.config_manager.load_config(require_pin=False).get(key)

    def set(self, key: str, value: str) -> None:
        cfg = self._manager.config_manager
        mapping = {
            "inactivity_timeout": ("set_inactivity_timeout", float),
            "secret_mode_enabled": (
                "set_secret_mode_enabled",
                lambda v: v.lower() in ("1", "true", "yes", "y", "on"),
            ),
            "clipboard_clear_delay": ("set_clipboard_clear_delay", int),
            "additional_backup_path": (
                "set_additional_backup_path",
                lambda v: v or None,
            ),
            "relays": ("set_relays", lambda v: (v, {"require_pin": False})),
            "kdf_iterations": ("set_kdf_iterations", int),
            "kdf_mode": ("set_kdf_mode", lambda v: v),
            "backup_interval": ("set_backup_interval", float),
            "nostr_max_retries": ("set_nostr_max_retries", int),
            "nostr_retry_delay": ("set_nostr_retry_delay", float),
            "min_uppercase": ("set_min_uppercase", int),
            "min_lowercase": ("set_min_lowercase", int),
            "min_digits": ("set_min_digits", int),
            "min_special": ("set_min_special", int),
            "include_special_chars": (
                "set_include_special_chars",
                lambda v: v.lower() in ("1", "true", "yes", "y", "on"),
            ),
            "allowed_special_chars": ("set_allowed_special_chars", lambda v: v),
            "special_mode": ("set_special_mode", lambda v: v),
            "exclude_ambiguous": (
                "set_exclude_ambiguous",
                lambda v: v.lower() in ("1", "true", "yes", "y", "on"),
            ),
            "quick_unlock": (
                "set_quick_unlock",
                lambda v: v.lower() in ("1", "true", "yes", "y", "on"),
            ),
        }
        entry = mapping.get(key)
        if entry is None:
            raise KeyError(key)
        method_name, conv = entry
        with self._lock:
            result = conv(value)
            if (
                isinstance(result, tuple)
                and len(result) == 2
                and isinstance(result[1], dict)
            ):
                arg, kwargs = result
                getattr(cfg, method_name)(arg, **kwargs)
            else:
                getattr(cfg, method_name)(result)

    def get_secret_mode_enabled(self) -> bool:
        with self._lock:
            return self._manager.config_manager.get_secret_mode_enabled()

    def get_clipboard_clear_delay(self) -> int:
        with self._lock:
            return self._manager.config_manager.get_clipboard_clear_delay()

    def set_secret_mode(self, enabled: bool, delay: int) -> None:
        with self._lock:
            cfg = self._manager.config_manager
            cfg.set_secret_mode_enabled(enabled)
            cfg.set_clipboard_clear_delay(delay)
            self._manager.secret_mode_enabled = enabled
            self._manager.clipboard_clear_delay = delay

    def get_offline_mode(self) -> bool:
        with self._lock:
            return self._manager.config_manager.get_offline_mode()

    def set_offline_mode(self, enabled: bool) -> None:
        with self._lock:
            cfg = self._manager.config_manager
            cfg.set_offline_mode(enabled)
            self._manager.offline_mode = enabled


class UtilityService:
    """Miscellaneous helper operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def generate_password(self, length: int) -> str:
        with self._lock:
            return self._manager.password_generator.generate_password(length)

    def verify_checksum(self) -> None:
        with self._lock:
            self._manager.handle_verify_checksum()

    def update_checksum(self) -> None:
        with self._lock:
            self._manager.handle_update_script_checksum()


class NostrService:
    """Nostr related helper methods."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def get_pubkey(self) -> str:
        with self._lock:
            return self._manager.nostr_client.key_manager.get_npub()

    def list_relays(self) -> list[str]:
        with self._lock:
            return self._manager.state_manager.list_relays()

    def add_relay(self, url: str) -> None:
        with self._lock:
            self._manager.state_manager.add_relay(url)
            self._manager.nostr_client.relays = (
                self._manager.state_manager.list_relays()
            )

    def remove_relay(self, idx: int) -> None:
        with self._lock:
            self._manager.state_manager.remove_relay(idx)
            self._manager.nostr_client.relays = (
                self._manager.state_manager.list_relays()
            )
