from __future__ import annotations

"""Service layer wrapping :class:`PasswordManager` operations.

These services provide thread-safe methods for common operations used by the CLI
and API. Request and response payloads are represented using Pydantic models to
allow easy validation and documentation.
"""

from pathlib import Path
from threading import Lock, RLock
from typing import List, Optional, Dict, Any
import dataclasses
import json
import time

from pydantic import BaseModel, Field

from .manager import PasswordManager
from .pubsub import bus
from .entry_types import EntryType
from .index0 import derive_index0_context, get_canonical_view, list_canonical_views
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


class SearchResult(BaseModel):
    """Normalized search result used across UI surfaces."""

    entry_id: int
    label: str
    kind: str
    scope_path: str
    archived: bool = False
    score: float = 0.0
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    match_reasons: list[str] = Field(default_factory=list)
    excerpt: str = ""
    linked_hits: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    modified_ts: int = 0
    meta: str = ""


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

    def get_pgp_key(self, entry_id: int) -> tuple[str, str, str]:
        """Return ``(private_key_armored, public_key_armored, fingerprint)`` for a PGP entry."""
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

    def delete_entry(self, entry_id: int) -> None:
        with self._lock:
            self._manager.entry_manager.delete_entry(entry_id)
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


class SearchService:
    """Thread-safe unified search wrapper for lexical, semantic, and atlas-aware ranking."""

    _SECRET_EXCERPT_KINDS = {
        "password",
        "stored_password",
        "totp",
        "seed",
        "managed_account",
        "ssh",
        "pgp",
        "nostr",
    }
    _SEMANTIC_MODES = {"hybrid", "semantic"}

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = RLock()

    def _scope_path(self) -> str:
        profile_dir = getattr(self._manager, "fingerprint_dir", None)
        if profile_dir is None:
            return ""
        return derive_index0_context(profile_dir)["scope_path"]

    def _all_entries(self) -> list[dict[str, Any]]:
        em = getattr(self._manager, "entry_manager", None)
        if em is None:
            return []
        try:
            rows = em.search_entries(
                "",
                kinds=None,
                include_archived=True,
                archived_only=False,
            )
        except TypeError:
            rows = em.search_entries("", kinds=None)
        entries: list[dict[str, Any]] = []
        for row in rows:
            try:
                entry_id = int(row[0])
            except Exception:
                continue
            entry = em.retrieve_entry(entry_id)
            if isinstance(entry, dict) and entry:
                payload = dict(entry)
                payload.setdefault("id", entry_id)
                entries.append(payload)
        entries.sort(key=lambda item: int(item.get("id", 0) or 0))
        return entries

    @staticmethod
    def _entry_kind(entry: dict[str, Any]) -> str:
        return str(entry.get("kind") or entry.get("type") or "").strip().lower()

    @staticmethod
    def _normalize_kind_filters(kinds: list[str] | None) -> set[str]:
        if not kinds:
            return set()
        return {
            str(kind).strip().lower() for kind in kinds if str(kind).strip().lower()
        }

    @staticmethod
    def _safe_excerpt(entry: dict[str, Any], kind: str) -> str:
        fields = ["notes"]
        if kind in {"document", "note"}:
            fields.append("content")
        elif kind in {"password", "stored_password"}:
            fields.extend(["username", "url"])
        elif kind == "key_value":
            fields.append("key")
        elif kind == "totp":
            fields.append("issuer")
        elif kind == "nostr":
            fields.append("npub")
        elif kind in {"ssh", "pgp"}:
            fields.append("fingerprint")
        for field in fields:
            value = str(entry.get(field, "")).strip()
            if value:
                return value[:220]
        return ""

    @staticmethod
    def _meta(entry: dict[str, Any], kind: str) -> str:
        for field in ("username", "url", "key", "file_type"):
            value = str(entry.get(field, "")).strip()
            if value:
                return value
        if kind == "managed_account":
            return "managed"
        return ""

    @staticmethod
    def _custom_field_text(entry: dict[str, Any]) -> str:
        parts: list[str] = []
        raw_fields = entry.get("custom_fields", [])
        if not isinstance(raw_fields, list):
            return ""
        for item in raw_fields:
            if not isinstance(item, dict):
                continue
            for key in ("name", "label", "key", "value"):
                value = str(item.get(key, "")).strip()
                if value:
                    parts.append(value)
        return "\n".join(parts)

    @staticmethod
    def _normalized_tags(entry: dict[str, Any]) -> list[str]:
        raw = entry.get("tags", [])
        if not isinstance(raw, list):
            return []
        tags = sorted({str(tag).strip() for tag in raw if str(tag).strip()})
        return tags

    @staticmethod
    def _normalized_links(entry: dict[str, Any]) -> list[dict[str, Any]]:
        raw = entry.get("links", [])
        if not isinstance(raw, list):
            return []
        links: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                target_id = int(item.get("target_id", 0))
            except Exception:
                continue
            relation = str(item.get("relation", "")).strip()
            note = str(item.get("note", "")).strip()
            if target_id <= 0 or not relation:
                continue
            link = {"target_id": target_id, "relation": relation}
            if note:
                link["note"] = note
            links.append(link)
        links.sort(
            key=lambda link: (
                str(link.get("relation", "")),
                int(link.get("target_id", 0)),
                str(link.get("note", "")),
            )
        )
        return links

    def _entry_search_text(self, entry: dict[str, Any], kind: str) -> str:
        parts = [
            SemanticIndex._extract_text(entry, kind),
            self._custom_field_text(entry),
        ]
        return "\n".join(part for part in parts if str(part).strip())

    def _semantic_scores(
        self,
        query: str,
        *,
        limit: int,
        mode: str,
    ) -> dict[int, dict[str, Any]]:
        if not query or mode not in self._SEMANTIC_MODES:
            return {}
        cfg = getattr(self._manager, "config_manager", None)
        if cfg is not None:
            try:
                if not bool(cfg.get_semantic_index_enabled()):
                    return {}
            except Exception:
                pass
        rows = SemanticIndexService(self._manager).search(
            query, k=max(10, int(limit)), mode="semantic"
        )
        out: dict[int, dict[str, Any]] = {}
        for row in rows:
            try:
                entry_id = int(row.get("entry_id", 0))
            except Exception:
                continue
            if entry_id <= 0:
                continue
            out[entry_id] = row
        return out

    @staticmethod
    def _recency_score(modified_ts: int) -> float:
        ts = int(modified_ts or 0)
        if ts <= 0:
            return 0.0
        age_days = max(0.0, (time.time() - float(ts)) / 86400.0)
        return round(1.0 / (1.0 + age_days), 6)

    def search(
        self,
        query: str,
        *,
        kinds: list[str] | None = None,
        include_archived: bool = False,
        archived_only: bool = False,
        mode: str | None = None,
        sort: str = "relevance",
        limit: int = 200,
        tags: list[str] | None = None,
        linked_to: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            scope_path = self._scope_path()
            active_mode = str(mode or "").strip().lower()
            if active_mode not in {"keyword", "hybrid", "semantic"}:
                cfg = getattr(self._manager, "config_manager", None)
                if cfg is not None:
                    try:
                        active_mode = (
                            str(cfg.get_semantic_search_mode()).strip().lower()
                        )
                    except Exception:
                        active_mode = "keyword"
                else:
                    active_mode = "keyword"
            if active_mode not in {"keyword", "hybrid", "semantic"}:
                active_mode = "keyword"

            semantic_scores = self._semantic_scores(
                query, limit=max(10, int(limit)), mode=active_mode
            )
            query_tokens = SemanticIndex._tokenize(str(query or ""))
            kind_filters = self._normalize_kind_filters(kinds)
            tag_filters = {
                str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()
            }
            atlas_recent = {}
            try:
                payload = self._manager.vault.load_index()
                index0 = payload.get("_system", {}).get("index0", {})
                recent = get_canonical_view(
                    index0, view_type="recent_activity", scope_path=scope_path
                )
                for idx, item in enumerate(recent.get("data", {}).get("items", [])):
                    try:
                        subject_id = int(item.get("subject_id", 0))
                    except Exception:
                        continue
                    atlas_recent[subject_id] = max(
                        atlas_recent.get(subject_id, 0.0), 1.0 - (idx * 0.1)
                    )
            except Exception:
                atlas_recent = {}

            results: list[dict[str, Any]] = []
            for entry in self._all_entries():
                entry_id = int(entry.get("id", 0) or 0)
                if entry_id <= 0:
                    continue
                kind = self._entry_kind(entry)
                if kind_filters and kind not in kind_filters:
                    continue
                archived = bool(entry.get("archived", False))
                if archived_only and not archived:
                    continue
                if not include_archived and archived:
                    continue
                tags_list = self._normalized_tags(entry)
                tags_lower = {tag.lower() for tag in tags_list}
                if tag_filters and not tag_filters.issubset(tags_lower):
                    continue
                links = self._normalized_links(entry)
                if linked_to is not None and not any(
                    int(link.get("target_id", 0)) == int(linked_to) for link in links
                ):
                    continue

                lexical_score = 0.0
                structural_score = 0.0
                semantic_score = 0.0
                recency_score = 0.0
                reasons: list[str] = []
                linked_hits: list[dict[str, Any]] = []

                modified_ts = int(entry.get("modified_ts", 0) or 0)
                if query_tokens:
                    label = str(entry.get("label", "")).strip()
                    label_tokens = SemanticIndex._tokenize(label)
                    search_text = self._entry_search_text(entry, kind)
                    text_tokens = SemanticIndex._tokenize(search_text)
                    text_overlap = len(query_tokens.intersection(text_tokens))
                    lexical_score = min(
                        1.0, text_overlap / float(len(query_tokens) or 1)
                    )
                    if label and str(query).strip().lower() == label.lower():
                        lexical_score = max(lexical_score, 1.0)
                        reasons.append("label_exact")
                    elif query_tokens.intersection(label_tokens):
                        reasons.append("label_match")
                    matching_tags = sorted(
                        tag for tag in tags_list if tag.lower() in query_tokens
                    )
                    if matching_tags:
                        structural_score += min(1.0, 0.25 * len(matching_tags))
                        reasons.extend(f"tag:{tag}" for tag in matching_tags)
                    for link in links:
                        relation_tokens = SemanticIndex._tokenize(
                            " ".join(
                                [
                                    str(link.get("relation", "")),
                                    str(link.get("note", "")),
                                ]
                            )
                        )
                        if query_tokens.intersection(relation_tokens):
                            linked_hits.append(
                                {
                                    "target_id": int(link.get("target_id", 0)),
                                    "relation": str(link.get("relation", "")),
                                }
                            )
                    if linked_hits:
                        structural_score += min(1.0, 0.2 + (0.1 * len(linked_hits)))
                        reasons.append("link_match")
                    semantic_row = semantic_scores.get(entry_id)
                    if semantic_row is not None:
                        semantic_score = float(semantic_row.get("score", 0.0))
                        reasons.append("semantic_match")
                    recency_score = min(
                        1.0,
                        max(
                            atlas_recent.get(entry_id, 0.0),
                            self._recency_score(modified_ts),
                        ),
                    )
                else:
                    linked_hits = [
                        {
                            "target_id": int(link.get("target_id", 0)),
                            "relation": str(link.get("relation", "")),
                        }
                        for link in links[:5]
                    ]
                    structural_score = min(1.0, 0.1 * len(links))
                    recency_score = atlas_recent.get(entry_id, 0.0)

                if linked_to is not None:
                    reasons.append(f"linked_to:{linked_to}")
                    structural_score = min(1.0, structural_score + 0.35)

                if query_tokens and not any(
                    score > 0.0
                    for score in (
                        lexical_score,
                        structural_score,
                        semantic_score,
                    )
                ):
                    continue

                if active_mode == "keyword":
                    total_score = (lexical_score * 0.8) + (structural_score * 0.15)
                    total_score += recency_score * 0.05
                    semantic_score = 0.0
                elif active_mode == "semantic":
                    total_score = (semantic_score * 0.7) + (structural_score * 0.2)
                    total_score += recency_score * 0.1
                    total_score += lexical_score * 0.0
                else:
                    total_score = (lexical_score * 0.4) + (semantic_score * 0.35)
                    total_score += structural_score * 0.2
                    total_score += recency_score * 0.05

                result = SearchResult(
                    entry_id=entry_id,
                    label=str(entry.get("label", "")).strip(),
                    kind=kind,
                    scope_path=scope_path,
                    archived=archived,
                    score=round(total_score, 6),
                    score_breakdown={
                        "lexical": round(lexical_score, 6),
                        "semantic": round(semantic_score, 6),
                        "structural": round(structural_score, 6),
                        "recency": round(recency_score, 6),
                    },
                    match_reasons=sorted(set(reasons)),
                    excerpt=(
                        ""
                        if kind in self._SECRET_EXCERPT_KINDS
                        else self._safe_excerpt(entry, kind)
                    ),
                    linked_hits=linked_hits,
                    tags=tags_list,
                    modified_ts=modified_ts,
                    meta=self._meta(entry, kind),
                ).model_dump()
                results.append(result)

            sort_key = str(sort or "relevance").strip().lower()

            def _result_key(item: dict[str, Any]) -> tuple[Any, ...]:
                label = str(item.get("label", "")).lower()
                kind = str(item.get("kind", "")).lower()
                modified_ts = int(item.get("modified_ts", 0) or 0)
                linked_count = len(item.get("linked_hits", []))
                entry_id = int(item.get("entry_id", 0))
                if sort_key == "modified_desc":
                    return (-modified_ts, label, entry_id)
                if sort_key == "modified_asc":
                    return (modified_ts, label, entry_id)
                if sort_key == "label_asc":
                    return (label, entry_id)
                if sort_key == "kind":
                    return (kind, label, entry_id)
                if sort_key == "most_linked":
                    return (-linked_count, label, entry_id)
                if sort_key == "created_desc":
                    created_ts = int(item.get("created_ts", modified_ts) or modified_ts)
                    return (-created_ts, label, entry_id)
                if query_tokens:
                    return (
                        -float(item.get("score", 0.0)),
                        -modified_ts,
                        label,
                        entry_id,
                    )
                return (entry_id,)

            results.sort(key=_result_key)
            return results[: max(1, int(limit))]

    def linked_neighbors(
        self,
        entry_id: int,
        *,
        relation: str | None = None,
        direction: str = "both",
        include_archived: bool = True,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        with self._lock:
            target_entry_id = int(entry_id or 0)
            if target_entry_id <= 0:
                return []

            direction_key = str(direction or "both").strip().lower()
            if direction_key not in {"incoming", "outgoing", "both"}:
                direction_key = "both"
            relation_filter = str(relation or "").strip().lower()
            scope_path = self._scope_path()

            entries = self._all_entries()
            entry_map = {
                int(item.get("id", 0) or 0): item
                for item in entries
                if int(item.get("id", 0) or 0) > 0
            }
            current_entry = entry_map.get(target_entry_id)
            if current_entry is None:
                return []

            neighbors: list[dict[str, Any]] = []

            if direction_key in {"outgoing", "both"}:
                for link in self._normalized_links(current_entry):
                    link_relation = str(link.get("relation", "")).strip().lower()
                    if relation_filter and link_relation != relation_filter:
                        continue
                    neighbor_id = int(link.get("target_id", 0) or 0)
                    neighbor = entry_map.get(neighbor_id)
                    if neighbor is None:
                        continue
                    archived = bool(neighbor.get("archived", False))
                    if not include_archived and archived:
                        continue
                    kind = self._entry_kind(neighbor)
                    neighbors.append(
                        {
                            "entry_id": neighbor_id,
                            "label": str(neighbor.get("label", "")).strip(),
                            "kind": kind,
                            "scope_path": scope_path,
                            "archived": archived,
                            "direction": "outgoing",
                            "relation": link_relation,
                            "note": str(link.get("note", "")).strip(),
                            "tags": self._normalized_tags(neighbor),
                            "meta": self._meta(neighbor, kind),
                        }
                    )

            if direction_key in {"incoming", "both"}:
                for source in entries:
                    source_id = int(source.get("id", 0) or 0)
                    if source_id <= 0 or source_id == target_entry_id:
                        continue
                    archived = bool(source.get("archived", False))
                    if not include_archived and archived:
                        continue
                    for link in self._normalized_links(source):
                        if int(link.get("target_id", 0) or 0) != target_entry_id:
                            continue
                        link_relation = str(link.get("relation", "")).strip().lower()
                        if relation_filter and link_relation != relation_filter:
                            continue
                        kind = self._entry_kind(source)
                        neighbors.append(
                            {
                                "entry_id": source_id,
                                "label": str(source.get("label", "")).strip(),
                                "kind": kind,
                                "scope_path": scope_path,
                                "archived": archived,
                                "direction": "incoming",
                                "relation": link_relation,
                                "note": str(link.get("note", "")).strip(),
                                "tags": self._normalized_tags(source),
                                "meta": self._meta(source, kind),
                            }
                        )

            neighbors.sort(
                key=lambda item: (
                    str(item.get("direction", "")),
                    str(item.get("relation", "")),
                    str(item.get("label", "")).lower(),
                    int(item.get("entry_id", 0) or 0),
                )
            )
            return neighbors[: max(1, int(limit))]

    def relation_summary(
        self,
        entry_id: int,
        *,
        include_archived: bool = True,
    ) -> dict[str, dict[str, int]]:
        neighbors = self.linked_neighbors(
            entry_id,
            include_archived=include_archived,
            direction="both",
            limit=1000,
        )
        summary = {
            "incoming": {},
            "outgoing": {},
            "combined": {},
        }
        for item in neighbors:
            relation = str(item.get("relation", "")).strip().lower()
            direction = str(item.get("direction", "")).strip().lower()
            if not relation or direction not in {"incoming", "outgoing"}:
                continue
            summary[direction][relation] = summary[direction].get(relation, 0) + 1
            summary["combined"][relation] = summary["combined"].get(relation, 0) + 1
        return {
            key: dict(sorted(value.items()))
            for key, value in summary.items()
        }

    def multi_hop_neighbors(
        self,
        entry_id: int,
        *,
        hops: int = 2,
        relation: str | None = None,
        direction: str = "both",
        kinds: list[str] | None = None,
        include_archived: bool = True,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return all neighbors reachable within ``hops`` graph hops from ``entry_id``.

        Each result includes ``hop`` (1-indexed distance from origin) and ``path``
        (ordered list of entry_ids from origin to this neighbor). Direct neighbors
        have ``hop=1``. When the same entry is reachable via multiple paths only
        the shortest-hop path is retained.
        """
        with self._lock:
            target_id = int(entry_id or 0)
            if target_id <= 0:
                return []
            hops = max(1, int(hops or 1))
            direction_key = str(direction or "both").strip().lower()
            if direction_key not in {"incoming", "outgoing", "both"}:
                direction_key = "both"
            relation_filter = str(relation or "").strip().lower()
            kind_filters = self._normalize_kind_filters(kinds)
            scope_path = self._scope_path()

            entries = self._all_entries()
            entry_map: dict[int, dict[str, Any]] = {
                int(e.get("id", 0) or 0): e
                for e in entries
                if int(e.get("id", 0) or 0) > 0
            }

            # BFS: visited maps neighbor_id -> best result dict
            visited: dict[int, dict[str, Any]] = {}
            # frontier: (current_id, current_hop, path_so_far)
            frontier: list[tuple[int, int, list[int]]] = [
                (target_id, 0, [target_id])
            ]

            while frontier:
                next_frontier: list[tuple[int, int, list[int]]] = []
                for current_id, current_hop, path in frontier:
                    if current_hop >= hops:
                        continue
                    current_entry = entry_map.get(current_id)
                    if current_entry is None:
                        continue
                    path_set = set(path)

                    if direction_key in {"outgoing", "both"}:
                        for link in self._normalized_links(current_entry):
                            link_relation = str(link.get("relation", "")).strip().lower()
                            if relation_filter and link_relation != relation_filter:
                                continue
                            neighbor_id = int(link.get("target_id", 0) or 0)
                            if neighbor_id <= 0 or neighbor_id == target_id:
                                continue
                            neighbor = entry_map.get(neighbor_id)
                            if neighbor is None:
                                continue
                            archived = bool(neighbor.get("archived", False))
                            if not include_archived and archived:
                                continue
                            neighbor_kind = self._entry_kind(neighbor)
                            if kind_filters and neighbor_kind not in kind_filters:
                                continue
                            hop_num = current_hop + 1
                            neighbor_path = path + [neighbor_id]
                            if (
                                neighbor_id not in visited
                                or visited[neighbor_id]["hop"] > hop_num
                            ):
                                visited[neighbor_id] = {
                                    "entry_id": neighbor_id,
                                    "label": str(neighbor.get("label", "")).strip(),
                                    "kind": neighbor_kind,
                                    "scope_path": scope_path,
                                    "archived": archived,
                                    "direction": "outgoing",
                                    "relation": link_relation,
                                    "note": str(link.get("note", "")).strip(),
                                    "tags": self._normalized_tags(neighbor),
                                    "meta": self._meta(neighbor, neighbor_kind),
                                    "hop": hop_num,
                                    "path": list(neighbor_path),
                                }
                            if hop_num < hops and neighbor_id not in path_set:
                                next_frontier.append(
                                    (neighbor_id, hop_num, neighbor_path)
                                )

                    if direction_key in {"incoming", "both"}:
                        for source in entries:
                            source_id = int(source.get("id", 0) or 0)
                            if source_id <= 0 or source_id == target_id or source_id in path_set:
                                continue
                            archived = bool(source.get("archived", False))
                            if not include_archived and archived:
                                continue
                            for link in self._normalized_links(source):
                                if int(link.get("target_id", 0) or 0) != current_id:
                                    continue
                                link_relation = str(link.get("relation", "")).strip().lower()
                                if relation_filter and link_relation != relation_filter:
                                    continue
                                source_kind = self._entry_kind(source)
                                if kind_filters and source_kind not in kind_filters:
                                    continue
                                hop_num = current_hop + 1
                                source_path = path + [source_id]
                                if (
                                    source_id not in visited
                                    or visited[source_id]["hop"] > hop_num
                                ):
                                    visited[source_id] = {
                                        "entry_id": source_id,
                                        "label": str(source.get("label", "")).strip(),
                                        "kind": source_kind,
                                        "scope_path": scope_path,
                                        "archived": archived,
                                        "direction": "incoming",
                                        "relation": link_relation,
                                        "note": str(link.get("note", "")).strip(),
                                        "tags": self._normalized_tags(source),
                                        "meta": self._meta(source, source_kind),
                                        "hop": hop_num,
                                        "path": list(source_path),
                                    }
                                if hop_num < hops and source_id not in path_set:
                                    next_frontier.append(
                                        (source_id, hop_num, source_path)
                                    )
                frontier = next_frontier

            results = sorted(
                visited.values(),
                key=lambda item: (
                    int(item.get("hop", 1)),
                    str(item.get("direction", "")),
                    str(item.get("relation", "")),
                    str(item.get("label", "")).lower(),
                    int(item.get("entry_id", 0) or 0),
                ),
            )
            return results[: max(1, int(limit))]

    def filtered_neighbors(
        self,
        entry_id: int,
        *,
        kinds: list[str] | None = None,
        relation: str | None = None,
        direction: str = "both",
        include_archived: bool = True,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return direct neighbors filtered by entry kind(s).

        Convenience wrapper around :meth:`linked_neighbors` that applies an
        additional kind-based filter. When ``kinds`` is ``None`` or empty this
        is equivalent to calling :meth:`linked_neighbors` directly.
        """
        if not kinds:
            return self.linked_neighbors(
                entry_id,
                relation=relation,
                direction=direction,
                include_archived=include_archived,
                limit=limit,
            )
        return self.multi_hop_neighbors(
            entry_id,
            hops=1,
            relation=relation,
            direction=direction,
            kinds=kinds,
            include_archived=include_archived,
            limit=limit,
        )


class AtlasService:
    """Thread-safe wrapper around canonical atlas/index0 read operations."""

    def __init__(self, manager: PasswordManager) -> None:
        self._manager = manager
        self._lock = Lock()

    def _payload(self) -> dict[str, Any]:
        vault = getattr(self._manager, "vault", None)
        if vault is None:
            raise ValueError("vault unavailable")
        return vault.load_index()

    def _scope_path(self) -> str:
        profile_dir = getattr(self._manager, "fingerprint_dir", None)
        if profile_dir is None:
            raise ValueError("active profile directory unavailable")
        return derive_index0_context(profile_dir)["scope_path"]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            payload = self._payload()
            index0 = payload.get("_system", {}).get("index0", {})
            return {
                "scope_path": self._scope_path(),
                "stats": dict(index0.get("stats", {})),
                "view_count": len(index0.get("canonical_views", {})),
                "view_types": list(
                    index0.get("view_manifest", {}).get("canonical_view_types", [])
                ),
            }

    def list_views(self) -> list[dict[str, Any]]:
        with self._lock:
            payload = self._payload()
            index0 = payload.get("_system", {}).get("index0", {})
            return list_canonical_views(index0)

    def get_view(
        self, view_type: str, *, scope_path: str | None = None
    ) -> dict[str, Any] | None:
        with self._lock:
            payload = self._payload()
            index0 = payload.get("_system", {}).get("index0", {})
            scope = scope_path or self._scope_path()
            return get_canonical_view(index0, view_type=view_type, scope_path=scope)

    def wayfinder(self, *, scope_path: str | None = None) -> Dict[str, Any]:
        with self._lock:
            payload = self._payload()
            index0 = payload.get("_system", {}).get("index0", {})
            scope = scope_path or self._scope_path()
            return {
                "scope_path": scope,
                "stats": dict(index0.get("stats", {})),
                "children_of": get_canonical_view(
                    index0, view_type="children_of", scope_path=scope
                ),
                "counts_by_kind": get_canonical_view(
                    index0, view_type="counts_by_kind", scope_path=scope
                ),
                "recent_activity": get_canonical_view(
                    index0, view_type="recent_activity", scope_path=scope
                ),
            }


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
