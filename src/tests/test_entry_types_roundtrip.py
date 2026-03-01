from __future__ import annotations

from pathlib import Path

import pytest

from helpers import TEST_PASSWORD, TEST_SEED, create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.entry_types import ALL_ENTRY_TYPES, EntryType


def _make_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def _add_entry_for_type(entry_mgr: EntryManager, entry_type: EntryType) -> int:
    if entry_type == EntryType.PASSWORD:
        return entry_mgr.add_entry(
            "Password Entry",
            16,
            username="alice",
            url="https://example.com",
            notes="pw-note",
            tags=["auth"],
        )
    if entry_type == EntryType.TOTP:
        entry_mgr.add_totp(
            "TOTP Entry",
            TEST_SEED,
            deterministic=True,
            period=45,
            digits=8,
            notes="totp-note",
            tags=["otp"],
        )
        return 0
    if entry_type == EntryType.SSH:
        return entry_mgr.add_ssh_key("SSH Entry", TEST_SEED, notes="ssh-note")
    if entry_type == EntryType.SEED:
        return entry_mgr.add_seed(
            "Seed Entry", TEST_SEED, words_num=12, notes="seed-note", tags=["seed"]
        )
    if entry_type == EntryType.PGP:
        return entry_mgr.add_pgp_key(
            "PGP Entry",
            TEST_SEED,
            key_type="ed25519",
            user_id="alice@example.com",
            notes="pgp-note",
            tags=["pgp"],
        )
    if entry_type == EntryType.NOSTR:
        return entry_mgr.add_nostr_key("Nostr Entry", TEST_SEED, notes="nostr-note")
    if entry_type == EntryType.KEY_VALUE:
        return entry_mgr.add_key_value(
            "KV Entry",
            "api_key",
            "secret-value",
            notes="kv-note",
            tags=["kv"],
        )
    if entry_type == EntryType.MANAGED_ACCOUNT:
        return entry_mgr.add_managed_account(
            "Managed Entry", TEST_SEED, notes="managed-note", tags=["managed"]
        )
    if entry_type == EntryType.DOCUMENT:
        return entry_mgr.add_document(
            "Document Entry",
            "alpha\nbeta\ngamma",
            file_type="md",
            notes="doc-note",
            tags=["doc"],
        )
    raise AssertionError(f"Unhandled entry type in test: {entry_type}")


def test_all_entry_type_values_are_enum_backed():
    assert set(ALL_ENTRY_TYPES) == {entry_type.value for entry_type in EntryType}


@pytest.mark.parametrize("entry_type", list(EntryType))
def test_each_entry_type_roundtrip_retrieve_and_filter(tmp_path, entry_type: EntryType):
    entry_mgr = _make_entry_manager(tmp_path)
    index = _add_entry_for_type(entry_mgr, entry_type)

    entry = entry_mgr.retrieve_entry(index)
    assert entry is not None
    assert entry["type"] == entry_type.value
    assert entry["kind"] == entry_type.value
    assert entry["label"]
    assert "modified_ts" not in entry
    assert "date_added" in entry
    assert "date_modified" in entry

    entries = entry_mgr.list_entries(
        filter_kinds=[entry_type.value], include_archived=True, verbose=False
    )
    assert len(entries) == 1
    listed_index, listed_label, listed_username, listed_url, listed_archived = entries[
        0
    ]
    assert listed_index == index
    assert listed_label == entry["label"]
    assert listed_archived is False

    if entry_type == EntryType.PASSWORD:
        assert listed_username == "alice"
        assert listed_url == "https://example.com"
        assert entry["length"] == 16
        assert entry["notes"] == "pw-note"
    else:
        assert listed_username is None
        assert listed_url is None

    if entry_type == EntryType.TOTP:
        assert entry["deterministic"] is True
        assert entry["period"] == 45
        assert entry["digits"] == 8
    if entry_type == EntryType.SSH:
        assert "index" in entry
    if entry_type == EntryType.SEED:
        assert entry["word_count"] == 12
    if entry_type == EntryType.PGP:
        assert entry["key_type"] == "ed25519"
        assert entry["user_id"] == "alice@example.com"
    if entry_type == EntryType.NOSTR:
        assert "index" in entry
    if entry_type == EntryType.KEY_VALUE:
        assert entry["key"] == "api_key"
        assert entry["value"] == "secret-value"
    if entry_type == EntryType.MANAGED_ACCOUNT:
        assert entry["word_count"] == 12
        assert entry["fingerprint"]
    if entry_type == EntryType.DOCUMENT:
        assert entry["file_type"] == "md"
        assert "alpha" in entry["content"]


@pytest.mark.parametrize("entry_type", list(EntryType))
def test_each_entry_type_sets_and_updates_dates(
    tmp_path, monkeypatch, entry_type: EntryType
):
    entry_mgr = _make_entry_manager(tmp_path)
    monkeypatch.setattr(entry_mgr, "_now_unix", lambda: 100)
    index = _add_entry_for_type(entry_mgr, entry_type)
    created = entry_mgr.retrieve_entry(index)
    assert created is not None
    assert created["date_added"] == entry_mgr._iso_from_unix(100)
    assert created["date_modified"] == entry_mgr._iso_from_unix(100)

    monkeypatch.setattr(entry_mgr, "_now_unix", lambda: 200)
    entry_mgr.modify_entry(index, label=f"{created['label']} updated")
    updated = entry_mgr.retrieve_entry(index)
    assert updated is not None
    assert updated["date_added"] == entry_mgr._iso_from_unix(100)
    assert updated["date_modified"] == entry_mgr._iso_from_unix(200)
