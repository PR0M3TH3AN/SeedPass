from __future__ import annotations

"""Service layer wrapping :class:`PasswordManager` operations.

These services provide thread-safe methods for common operations used by the CLI
and API. Request and response payloads are represented using Pydantic models to
allow easy validation and documentation.
"""

from pathlib import Path
from threading import Lock
from typing import List, Optional, Dict, Any
import dataclasses
import json

from pydantic import BaseModel

from .manager import PasswordManager
from .pubsub import bus
from .entry_types import EntryType
from .semantic_index import SemanticIndex
from utils import copy_to_clipboard


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


class PasswordPolicyOptions(BaseModel):
    """Optional password policy overrides."""

    include_special_chars: bool | None = None
    allowed_special_chars: str | None = None
    special_mode: str | None = None
    exclude_ambiguous: bool | None = None
    min_uppercase: int | None = None
    min_lowercase: int | None = None
    min_digits: int | None = None
    min_special: int | None = None


class AddPasswordEntryRequest(PasswordPolicyOptions):
    label: str
    length: int
    username: str | None = None
    url: str | None = None


class GeneratePasswordRequest(PasswordPolicyOptions):
    length: int


class GeneratePasswordResponse(BaseModel):
    password: str


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
            decrypted = self._manager.vault.encryption_manager.decrypt_data(
                data, context="profile"
            )
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

    def rename_profile(self, fingerprint: str, name: str | None) -> None:
        """Set or clear a display name for ``fingerprint``."""

        with self._lock:
            ok = self._manager.fingerprint_manager.set_name(fingerprint, name)
            if not ok:
                raise ValueError("profile not found")


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
        filter_kinds: list[str] | None = None,
        include_archived: bool = False,
    ):
        with self._lock:
            return self._manager.entry_manager.list_entries(
                sort_by=sort_by,
                filter_kinds=filter_kinds,
                include_archived=include_archived,
            )

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ) -> list[tuple[int, str, str | None, str | None, bool, EntryType]]:
        """Search entries optionally filtering by ``kinds``.

        Parameters
        ----------
        query:
            Search string to match against entry metadata.
        kinds:
            Optional list of entry kinds to restrict the search.
        """

        with self._lock:
            rows = self._manager.entry_manager.search_entries(query, kinds=kinds)
        if not include_archived:
            return [row for row in rows if not bool(row[4])]
        if archived_only:
            return [row for row in rows if bool(row[4])]
        return rows

    def retrieve_entry(self, entry_id: int):
        with self._lock:
            return self._manager.entry_manager.retrieve_entry(entry_id)

    def generate_password(self, length: int, index: int) -> str:
        with self._lock:
            entry = self._manager.entry_manager.retrieve_entry(index)
            gen_fn = getattr(self._manager, "_generate_password_for_entry", None)
            if gen_fn is None:
                return self._manager.password_generator.generate_password(length, index)
            return gen_fn(entry, index, length)

    def get_totp_code(self, entry_id: int) -> str:
        with self._lock:
            key = getattr(self._manager, "KEY_TOTP_DET", None) or getattr(
                self._manager, "parent_seed", None
            )
            return self._manager.entry_manager.get_totp_code(entry_id, key)

    def get_totp_secret(self, entry_id: int) -> str:
        """Return the TOTP secret (base32) for the given entry."""
        with self._lock:
            return self._manager.entry_manager.get_totp_secret(
                entry_id, self._manager.parent_seed
            )

    def get_seed_phrase(self, entry_id: int) -> str:
        """Return the derived seed phrase for a seed entry."""
        with self._lock:
            return self._manager.entry_manager.get_seed_phrase(
                entry_id, self._manager.parent_seed
            )

    def get_managed_account_seed(self, entry_id: int) -> str:
        """Return the derived seed phrase for a managed account entry."""
        with self._lock:
            return self._manager.entry_manager.get_managed_account_seed(
                entry_id, self._manager.parent_seed
            )

    def get_ssh_key_pair(self, entry_id: int) -> tuple[str, str]:
        """Return ``(private_key_pem, public_key_pem)`` for an SSH entry."""
        with self._lock:
            return self._manager.entry_manager.get_ssh_key_pair(
                entry_id, self._manager.parent_seed
            )

    def get_pgp_key(self, entry_id: int) -> tuple[str, str]:
        """Return ``(private_key_armored, fingerprint)`` for a PGP entry."""
        with self._lock:
            return self._manager.entry_manager.get_pgp_key(
                entry_id, self._manager.parent_seed
            )

    def get_nostr_key_pair(self, entry_id: int) -> tuple[str, str]:
        """Return ``(npub, nsec)`` for a Nostr entry."""
        with self._lock:
            return self._manager.entry_manager.get_nostr_key_pair(
                entry_id, self._manager.parent_seed
            )

    def get_secret_mode_enabled(self) -> bool:
        """Return whether secret mode is currently enabled."""
        with self._lock:
            cfg = getattr(self._manager, "config_manager", None)
            if cfg is not None:
                try:
                    return bool(cfg.get_secret_mode_enabled())
                except Exception:
                    pass
            return bool(getattr(self._manager, "secret_mode_enabled", False))

    def get_clipboard_clear_delay(self) -> int:
        """Return clipboard clear delay in seconds."""
        with self._lock:
            cfg = getattr(self._manager, "config_manager", None)
            if cfg is not None:
                try:
                    return int(cfg.get_clipboard_clear_delay())
                except Exception:
                    pass
            return int(getattr(self._manager, "clipboard_clear_delay", 30))

    def copy_to_clipboard(self, value: str) -> bool:
        """Copy ``value`` to clipboard using configured clear delay."""
        with self._lock:
            cfg = getattr(self._manager, "config_manager", None)
            if cfg is not None:
                try:
                    delay = int(cfg.get_clipboard_clear_delay())
                except Exception:
                    delay = int(getattr(self._manager, "clipboard_clear_delay", 30))
            else:
                delay = int(getattr(self._manager, "clipboard_clear_delay", 30))
            return copy_to_clipboard(value, delay)

    def add_entry(
        self,
        label: str,
        length: int,
        username: str | None = None,
        url: str | None = None,
        *,
        include_special_chars: bool | None = None,
        allowed_special_chars: str | None = None,
        special_mode: str | None = None,
        exclude_ambiguous: bool | None = None,
        min_uppercase: int | None = None,
        min_lowercase: int | None = None,
        min_digits: int | None = None,
        min_special: int | None = None,
    ) -> int:
        with self._lock:
            kwargs: dict[str, Any] = {}
            if include_special_chars is not None:
                kwargs["include_special_chars"] = include_special_chars
            if allowed_special_chars is not None:
                kwargs["allowed_special_chars"] = allowed_special_chars
            if special_mode is not None:
                kwargs["special_mode"] = special_mode
            if exclude_ambiguous is not None:
                kwargs["exclude_ambiguous"] = exclude_ambiguous
            if min_uppercase is not None:
                kwargs["min_uppercase"] = min_uppercase
            if min_lowercase is not None:
                kwargs["min_lowercase"] = min_lowercase
            if min_digits is not None:
                kwargs["min_digits"] = min_digits
            if min_special is not None:
                kwargs["min_special"] = min_special

            idx = self._manager.entry_manager.add_entry(
                label,
                length,
                username,
                url,
                **kwargs,
            )
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
        deterministic: bool = False,
    ) -> str:
        with self._lock:
            key = self._manager.KEY_TOTP_DET if deterministic else None
            uri = self._manager.entry_manager.add_totp(
                label,
                key,
                index=index,
                secret=secret,
                period=period,
                digits=digits,
                deterministic=deterministic,
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
                self._manager.parent_seed,
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

    def add_document(
        self,
        label: str,
        content: str,
        *,
        file_type: str = "txt",
        notes: str = "",
        tags: list[str] | None = None,
        archived: bool = False,
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.add_document(
                label,
                content,
                file_type=file_type,
                notes=notes,
                tags=tags,
                archived=archived,
            )
            self._manager.start_background_vault_sync()
            return idx

    def import_document_file(
        self,
        file_path: str | Path,
        *,
        label: str | None = None,
        notes: str = "",
        tags: list[str] | None = None,
        archived: bool = False,
    ) -> int:
        with self._lock:
            idx = self._manager.entry_manager.import_document_file(
                file_path,
                label=label,
                notes=notes,
                tags=tags,
                archived=archived,
            )
            self._manager.start_background_vault_sync()
            return idx

    def export_document_file(
        self,
        entry_id: int,
        output_path: str | Path | None = None,
        *,
        overwrite: bool = False,
    ) -> Path:
        with self._lock:
            return self._manager.entry_manager.export_document_file(
                entry_id,
                output_path=output_path,
                overwrite=overwrite,
            )

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
        content: str | None = None,
        file_type: str | None = None,
        custom_fields: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        links: list[dict[str, Any]] | None = None,
        archived: bool | None = None,
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
                content=content,
                file_type=file_type,
                custom_fields=custom_fields,
                tags=tags,
                links=links,
                archived=archived,
            )
            self._manager.start_background_vault_sync()

    def add_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str = "related_to",
        note: str = "",
    ) -> list[dict[str, Any]]:
        with self._lock:
            links = self._manager.entry_manager.add_link(
                entry_id, target_id, relation=relation, note=note
            )
            self._manager.start_background_vault_sync()
            return links

    def remove_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            links = self._manager.entry_manager.remove_link(
                entry_id, target_id, relation=relation
            )
            self._manager.start_background_vault_sync()
            return links

    def get_links(self, entry_id: int) -> list[dict[str, Any]]:
        with self._lock:
            return self._manager.entry_manager.get_links(entry_id)

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
            key = getattr(self._manager, "KEY_TOTP_DET", None) or getattr(
                self._manager, "parent_seed", None
            )
            return self._manager.entry_manager.export_totp_entries(key)

    def display_totp_codes(self) -> None:
        with self._lock:
            self._manager.handle_display_totp_codes()

    def load_managed_account(self, entry_id: int) -> None:
        with self._lock:
            self._manager.load_managed_account(int(entry_id))

    def exit_managed_account(self) -> None:
        with self._lock:
            self._manager.exit_managed_account()


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
            "semantic_search_mode": ("set_semantic_search_mode", lambda v: v),
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

    def set_semantic_index_enabled(self, enabled: bool) -> None:
        with self._lock:
            cfg = self._manager.config_manager
            cfg.set_semantic_index_enabled(enabled)

    def get_semantic_index_enabled(self) -> bool:
        with self._lock:
            return self._manager.config_manager.get_semantic_index_enabled()

    def set_semantic_search_mode(self, mode: str) -> None:
        with self._lock:
            self._manager.config_manager.set_semantic_search_mode(mode)

    def get_semantic_search_mode(self) -> str:
        with self._lock:
            return self._manager.config_manager.get_semantic_search_mode()


class SemanticIndexService:
    """Thread-safe wrapper around local semantic index operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def _index(self) -> SemanticIndex:
        profile_dir = getattr(self._manager, "fingerprint_dir", None)
        if profile_dir is None:
            raise ValueError("active profile directory unavailable")
        return SemanticIndex(Path(profile_dir))

    def _all_entries(self) -> list[dict[str, Any]]:
        em = getattr(self._manager, "entry_manager", None)
        if em is None:
            return []
        rows = em.search_entries(
            "",
            kinds=None,
            include_archived=True,
            archived_only=False,
        )
        entries: list[dict[str, Any]] = []
        for row in rows:
            try:
                entry_id = int(row[0])
            except Exception:
                continue
            entry = em.retrieve_entry(entry_id)
            if isinstance(entry, dict) and entry:
                entries.append(dict(entry))
        return entries

    def status(self) -> Dict[str, Any]:
        with self._lock:
            idx = self._index()
            payload = idx.status()
            payload["enabled"] = bool(
                self._manager.config_manager.get_semantic_index_enabled()
            )
            payload["mode"] = self._manager.config_manager.get_semantic_search_mode()
            return payload

    def set_enabled(self, enabled: bool) -> Dict[str, Any]:
        with self._lock:
            self._manager.config_manager.set_semantic_index_enabled(bool(enabled))
            idx = self._index()
            idx.set_enabled(bool(enabled))
            payload = idx.status()
            payload["enabled"] = bool(enabled)
            payload["mode"] = self._manager.config_manager.get_semantic_search_mode()
            return payload

    def set_mode(self, mode: str) -> Dict[str, Any]:
        with self._lock:
            self._manager.config_manager.set_semantic_search_mode(mode)
            idx = self._index()
            payload = idx.status()
            payload["enabled"] = bool(
                self._manager.config_manager.get_semantic_index_enabled()
            )
            payload["mode"] = self._manager.config_manager.get_semantic_search_mode()
            return payload

    def get_mode(self) -> str:
        with self._lock:
            return self._manager.config_manager.get_semantic_search_mode()

    def build(self) -> Dict[str, Any]:
        with self._lock:
            idx = self._index()
            idx.set_enabled(self._manager.config_manager.get_semantic_index_enabled())
            return idx.build(self._all_entries())

    def rebuild(self) -> Dict[str, Any]:
        with self._lock:
            idx = self._index()
            idx.set_enabled(self._manager.config_manager.get_semantic_index_enabled())
            return idx.rebuild(self._all_entries())

    def search(
        self,
        query: str,
        *,
        k: int = 10,
        kind: str | None = None,
        mode: str | None = None,
    ) -> list[Dict[str, Any]]:
        with self._lock:
            active_mode = (
                str(mode or self._manager.config_manager.get_semantic_search_mode())
                .strip()
                .lower()
            )
            if active_mode not in {"keyword", "hybrid", "semantic"}:
                active_mode = "keyword"
            if active_mode == "keyword":
                return self._lexical_search(query, k=k, kind=kind)
            idx = self._index()
            semantic_rows = idx.search(query, k=k, kind=kind)
            if active_mode == "semantic":
                return semantic_rows
            lexical_rows = self._lexical_search(query, k=k, kind=kind)
            return self._merge_hybrid(semantic_rows, lexical_rows, k=max(1, int(k)))

    def _lexical_search(
        self, query: str, *, k: int = 10, kind: str | None = None
    ) -> list[Dict[str, Any]]:
        em = getattr(self._manager, "entry_manager", None)
        if em is None:
            return []
        kinds = [kind] if kind else None
        rows = em.search_entries(
            str(query),
            kinds=kinds,
            include_archived=True,
            archived_only=False,
        )
        out: list[Dict[str, Any]] = []
        max_rows = max(1, int(k))
        for idx, row in enumerate(rows[:max_rows], start=1):
            try:
                entry_id = int(row[0])
            except Exception:
                continue
            label = str(row[1]) if len(row) > 1 else ""
            kind_value = ""
            if len(row) > 5:
                kind_cell = row[5]
                kind_value = str(getattr(kind_cell, "value", kind_cell))
            if not kind_value:
                kind_value = str(kind or "")
            entry = em.retrieve_entry(entry_id)
            excerpt = ""
            if isinstance(entry, dict):
                for field in ("notes", "content", "value", "username", "url"):
                    text = str(entry.get(field, "")).strip()
                    if text:
                        excerpt = text[:220]
                        break
            # lexical rank-based score in (0,1]
            score = 1.0 - ((idx - 1) / max(1, max_rows))
            out.append(
                {
                    "entry_id": entry_id,
                    "kind": kind_value,
                    "label": label,
                    "score": round(score, 6),
                    "excerpt": excerpt,
                }
            )
        return out

    @staticmethod
    def _merge_hybrid(
        semantic_rows: list[Dict[str, Any]],
        lexical_rows: list[Dict[str, Any]],
        *,
        k: int,
    ) -> list[Dict[str, Any]]:
        merged: dict[int, Dict[str, Any]] = {}
        for row in semantic_rows:
            entry_id = int(row.get("entry_id", 0))
            if entry_id <= 0:
                continue
            merged[entry_id] = {
                "entry_id": entry_id,
                "kind": str(row.get("kind", "")),
                "label": str(row.get("label", "")),
                "excerpt": str(row.get("excerpt", "")),
                "score": float(row.get("score", 0.0)) * 0.7,
            }
        for row in lexical_rows:
            entry_id = int(row.get("entry_id", 0))
            if entry_id <= 0:
                continue
            lex_boost = float(row.get("score", 0.0)) * 0.3
            current = merged.get(entry_id)
            if current is None:
                merged[entry_id] = {
                    "entry_id": entry_id,
                    "kind": str(row.get("kind", "")),
                    "label": str(row.get("label", "")),
                    "excerpt": str(row.get("excerpt", "")),
                    "score": lex_boost,
                }
                continue
            current["score"] = float(current.get("score", 0.0)) + lex_boost
            if not str(current.get("excerpt", "")).strip():
                current["excerpt"] = str(row.get("excerpt", ""))
            if not str(current.get("label", "")).strip():
                current["label"] = str(row.get("label", ""))
            if not str(current.get("kind", "")).strip():
                current["kind"] = str(row.get("kind", ""))
        items = list(merged.values())
        items.sort(
            key=lambda r: (-float(r.get("score", 0.0)), int(r.get("entry_id", 0)))
        )
        for row in items:
            row["score"] = round(float(row.get("score", 0.0)), 6)
        return items[: max(1, int(k))]


class UtilityService:
    """Miscellaneous helper operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def generate_password(
        self,
        length: int,
        *,
        include_special_chars: bool | None = None,
        allowed_special_chars: str | None = None,
        special_mode: str | None = None,
        exclude_ambiguous: bool | None = None,
        min_uppercase: int | None = None,
        min_lowercase: int | None = None,
        min_digits: int | None = None,
        min_special: int | None = None,
    ) -> str:
        with self._lock:
            pg = self._manager.password_generator
            base_policy = getattr(pg, "policy", None)
            overrides: dict[str, Any] = {}
            if include_special_chars is not None:
                overrides["include_special_chars"] = include_special_chars
            if allowed_special_chars is not None:
                overrides["allowed_special_chars"] = allowed_special_chars
            if special_mode is not None:
                overrides["special_mode"] = special_mode
            if exclude_ambiguous is not None:
                overrides["exclude_ambiguous"] = exclude_ambiguous
            if min_uppercase is not None:
                overrides["min_uppercase"] = int(min_uppercase)
            if min_lowercase is not None:
                overrides["min_lowercase"] = int(min_lowercase)
            if min_digits is not None:
                overrides["min_digits"] = int(min_digits)
            if min_special is not None:
                overrides["min_special"] = int(min_special)

            if base_policy is not None and overrides:
                pg.policy = dataclasses.replace(
                    base_policy,
                    **{k: overrides[k] for k in overrides if hasattr(base_policy, k)},
                )
                try:
                    return pg.generate_password(length)
                finally:
                    pg.policy = base_policy
            return pg.generate_password(length)

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

    def reset_relays(self) -> list[str]:
        with self._lock:
            from nostr.client import DEFAULT_RELAYS

            relays = list(DEFAULT_RELAYS)
            self._manager.config_manager.set_relays(relays, require_pin=False)
            state = self._manager.state_manager._load()
            state["relays"] = relays
            self._manager.state_manager._save(state)
            self._manager.nostr_client.relays = list(relays)
            return relays

    def _clear_runtime_sync_state(self) -> None:
        self._manager.manifest_id = None
        self._manager.delta_since = 0
        self._manager.last_sync_ts = 0
        client = getattr(self._manager, "nostr_client", None)
        if client is None:
            return
        if hasattr(client, "last_error"):
            client.last_error = None
        if hasattr(client, "current_manifest_id"):
            client.current_manifest_id = None
        if hasattr(client, "current_manifest"):
            client.current_manifest = None
        if hasattr(client, "_delta_events"):
            client._delta_events = []

    def reset_sync_state(self) -> int:
        """Reset manifest/delta sync metadata for the active profile."""
        with self._lock:
            state_mgr = getattr(self._manager, "state_manager", None)
            if state_mgr is None:
                raise ValueError("State manager unavailable for current profile.")
            state = getattr(state_mgr, "state", {}) or {}
            state_mgr.update_state(manifest_id=None, delta_since=0, last_sync_ts=0)
            self._clear_runtime_sync_state()
            idx = int(state.get("nostr_account_idx", 0))
            self._manager.nostr_account_idx = idx
            return idx

    def start_fresh_namespace(self) -> int:
        """Advance deterministic Nostr account index and reset sync metadata."""
        with self._lock:
            state_mgr = getattr(self._manager, "state_manager", None)
            if state_mgr is None:
                raise ValueError("State manager unavailable for current profile.")
            state = getattr(state_mgr, "state", {}) or {}
            next_idx = int(state.get("nostr_account_idx", 0)) + 1
            state_mgr.update_state(
                manifest_id=None,
                delta_since=0,
                last_sync_ts=0,
                nostr_account_idx=next_idx,
            )
            self._clear_runtime_sync_state()
            self._manager.nostr_account_idx = next_idx
            reinit = getattr(self._manager, "_initialize_nostr_client", None)
            if callable(reinit):
                reinit()
            return next_idx
