import pytest
from unittest.mock import MagicMock, patch, call
from pathlib import Path
from threading import Lock
import json
from dataclasses import dataclass

from seedpass.core.api import (
    VaultService,
    ProfileService,
    SyncService,
    EntryService,
    SearchService,
    ConfigService,
    UtilityService,
    NostrService,
    AtlasService,
    VaultExportRequest,
    VaultExportResponse,
    VaultImportRequest,
    ChangePasswordRequest,
    UnlockRequest,
    UnlockResponse,
    BackupParentSeedRequest,
    ProfileSwitchRequest,
    ProfileRemoveRequest,
    PasswordPolicyOptions,
    GeneratePasswordRequest,
    GeneratePasswordResponse,
    AddPasswordEntryRequest,
)
from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType


@dataclass
class MockPolicy:
    include_special_chars: bool = False
    min_uppercase: int = 0


@pytest.fixture
def mock_manager():
    """Create a mock PasswordManager with all sub-components mocked."""
    manager = MagicMock(spec=PasswordManager)

    # Mock sub-managers
    manager.entry_manager = MagicMock()
    manager.config_manager = MagicMock()
    manager.fingerprint_manager = MagicMock()
    manager.encryption_manager = MagicMock()
    manager.vault = MagicMock()
    manager.password_generator = MagicMock()
    manager.nostr_client = MagicMock()
    manager.state_manager = MagicMock()

    # Mock specific attributes
    manager.KEY_TOTP_DET = b"mock_totp_key"
    manager.parent_seed = "mock_parent_seed"
    manager.current_fingerprint = "fp1"

    return manager


@pytest.fixture
def mock_bus():
    """Mock the pubsub bus."""
    with patch("seedpass.core.api.bus") as mock:
        yield mock


class TestVaultService:
    @pytest.fixture
    def service(self, mock_manager):
        return VaultService(mock_manager)

    def test_export_vault(self, service, mock_manager):
        req = VaultExportRequest(path=Path("/tmp/export.json"))
        resp = service.export_vault(req)

        mock_manager.handle_export_database.assert_called_once_with(req.path)
        assert resp.path == req.path

    def test_import_vault(self, service, mock_manager):
        req = VaultImportRequest(path=Path("/tmp/import.json"))
        service.import_vault(req)

        mock_manager.handle_import_database.assert_called_once_with(req.path)
        mock_manager.sync_vault.assert_called_once()

    def test_export_profile(self, service, mock_manager):
        mock_index = {"entries": {}}
        mock_manager.vault.load_index.return_value = mock_index
        mock_manager.vault.encryption_manager.encrypt_data.return_value = b"encrypted"

        result = service.export_profile()

        mock_manager.vault.load_index.assert_called_once()
        expected_payload = json.dumps(
            mock_index, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        mock_manager.vault.encryption_manager.encrypt_data.assert_called_once_with(
            expected_payload
        )
        assert result == b"encrypted"

    def test_import_profile(self, service, mock_manager):
        data = b"encrypted_data"
        decrypted_json = json.dumps({"entries": {}})
        mock_manager.vault.encryption_manager.decrypt_data.return_value = (
            decrypted_json.encode("utf-8")
        )

        service.import_profile(data)

        mock_manager.vault.encryption_manager.decrypt_data.assert_called_once_with(
            data, context="profile"
        )
        mock_manager.vault.save_index.assert_called_once_with(
            json.loads(decrypted_json)
        )
        mock_manager.sync_vault.assert_called_once()

    def test_change_password(self, service, mock_manager):
        req = ChangePasswordRequest(old_password="old", new_password="new")
        service.change_password(req)

        mock_manager.change_password.assert_called_once_with("old", "new")

    def test_unlock(self, service, mock_manager):
        mock_manager.unlock_vault.return_value = 0.5
        req = UnlockRequest(password="secret")
        resp = service.unlock(req)

        mock_manager.unlock_vault.assert_called_once_with("secret")
        assert resp.duration == 0.5

    def test_lock(self, service, mock_manager):
        service.lock()
        mock_manager.lock_vault.assert_called_once()

    def test_backup_parent_seed(self, service, mock_manager):
        req = BackupParentSeedRequest(path=Path("/tmp/seed.enc"), password="pw")
        service.backup_parent_seed(req)

        mock_manager.handle_backup_reveal_parent_seed.assert_called_once_with(
            req.path, password=req.password
        )

    def test_stats(self, service, mock_manager):
        expected_stats = {"entries": 10}
        mock_manager.get_profile_stats.return_value = expected_stats

        stats = service.stats()

        mock_manager.get_profile_stats.assert_called_once()
        assert stats == expected_stats


class TestProfileService:
    @pytest.fixture
    def service(self, mock_manager):
        return ProfileService(mock_manager)

    def test_list_profiles(self, service, mock_manager):
        mock_manager.fingerprint_manager.list_fingerprints.return_value = ["fp1", "fp2"]
        profiles = service.list_profiles()

        mock_manager.fingerprint_manager.list_fingerprints.assert_called_once()
        assert profiles == ["fp1", "fp2"]

    def test_add_profile(self, service, mock_manager):
        mock_manager.fingerprint_manager.current_fingerprint = "new_fp"
        result = service.add_profile()

        mock_manager.add_new_fingerprint.assert_called_once()
        assert result == "new_fp"

    def test_remove_profile(self, service, mock_manager):
        req = ProfileRemoveRequest(fingerprint="fp1")
        service.remove_profile(req)

        mock_manager.fingerprint_manager.remove_fingerprint.assert_called_once_with(
            "fp1"
        )

    def test_switch_profile(self, service, mock_manager):
        req = ProfileSwitchRequest(fingerprint="fp2", password="pw")
        service.switch_profile(req)

        mock_manager.select_fingerprint.assert_called_once_with("fp2", password="pw")


class TestSyncService:
    @pytest.fixture
    def service(self, mock_manager):
        return SyncService(mock_manager)

    def test_sync(self, service, mock_manager, mock_bus):
        mock_result = {"manifest_id": "m1"}
        mock_manager.sync_vault.return_value = mock_result

        result = service.sync()

        mock_bus.publish.assert_has_calls(
            [call("sync_started"), call("sync_finished", mock_result)]
        )
        mock_manager.sync_vault.assert_called_once()
        assert result.manifest_id == "m1"

    def test_sync_none(self, service, mock_manager, mock_bus):
        mock_manager.sync_vault.return_value = None

        result = service.sync()

        mock_bus.publish.assert_has_calls(
            [call("sync_started"), call("sync_finished", None)]
        )
        assert result is None

    def test_start_background_sync(self, service, mock_manager):
        service.start_background_sync()
        mock_manager.start_background_sync.assert_called_once()

    def test_start_background_vault_sync(self, service, mock_manager):
        service.start_background_vault_sync("summary")
        mock_manager.start_background_vault_sync.assert_called_once_with("summary")


class TestEntryService:
    @pytest.fixture
    def service(self, mock_manager):
        return EntryService(mock_manager)

    def test_list_entries(self, service, mock_manager):
        mock_manager.entry_manager.list_entries.return_value = []
        entries = service.list_entries()

        mock_manager.entry_manager.list_entries.assert_called_once_with(
            sort_by="index", filter_kinds=None, include_archived=False
        )
        assert entries == []

    def test_search_entries(self, service, mock_manager):
        mock_manager.entry_manager.search_entries.return_value = []
        results = service.search_entries("query")

        mock_manager.entry_manager.search_entries.assert_called_once_with(
            "query", kinds=None
        )
        assert results == []

    def test_search_entries_default_excludes_archived(self, service, mock_manager):
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "active", None, None, False, EntryType.PASSWORD),
            (2, "archived", None, None, True, EntryType.PASSWORD),
        ]
        results = service.search_entries("q")
        assert [row[0] for row in results] == [1]


class TestAtlasService:
    @pytest.fixture
    def service(self, mock_manager):
        return AtlasService(mock_manager)

    def test_status(self, service, mock_manager, tmp_path):
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.vault.load_index.return_value = {
            "_system": {
                "index0": {
                    "stats": {"event_count": 3},
                    "canonical_views": {"a": {}, "b": {}},
                    "view_manifest": {"canonical_view_types": ["children_of"]},
                }
            }
        }

        status = service.status()

        assert status["stats"]["event_count"] == 3
        assert status["view_count"] == 2
        assert status["view_types"] == ["children_of"]

    def test_wayfinder(self, service, mock_manager, tmp_path):
        mock_manager.fingerprint_dir = tmp_path
        scope_path = f"seed/{tmp_path.name}"
        mock_manager.vault.load_index.return_value = {
            "_system": {
                "index0": {
                    "canonical_views": {
                        f"children_of:{scope_path}": {
                            "view_id": f"children_of:{scope_path}",
                            "view_type": "children_of",
                            "scope_path": scope_path,
                            "source_checkpoint_ids": [],
                            "source_event_ids": [],
                            "data": {"children": [{"entry_id": "1"}]},
                            "modified_ts": 1,
                            "view_hash": "abc",
                        },
                        f"counts_by_kind:{scope_path}": {
                            "view_id": f"counts_by_kind:{scope_path}",
                            "view_type": "counts_by_kind",
                            "scope_path": scope_path,
                            "source_checkpoint_ids": [],
                            "source_event_ids": [],
                            "data": {"counts": {"document": 1}},
                            "modified_ts": 1,
                            "view_hash": "def",
                        },
                    },
                    "stats": {"event_count": 2},
                }
            }
        }

        payload = service.wayfinder()

        assert payload["scope_path"] == scope_path
        assert payload["children_of"]["data"]["children"][0]["entry_id"] == "1"
        assert payload["counts_by_kind"]["data"]["counts"]["document"] == 1
        assert payload["recent_activity"] is None


class TestSearchService:
    @pytest.fixture
    def service(self, mock_manager):
        return SearchService(mock_manager)

    def test_keyword_search_returns_unified_results(
        self, service, mock_manager, tmp_path
    ):
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Project Plan", None, None, False, EntryType.DOCUMENT),
            (2, "Ops Vault", "ops", "https://ops", False, EntryType.PASSWORD),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Project Plan",
                "content": "SeedPass atlas project plan and roadmap",
                "tags": ["planning", "docs"],
                "links": [{"target_id": 2, "relation": "references"}],
                "modified_ts": 200,
            },
            2: {
                "id": 2,
                "kind": "password",
                "label": "Ops Vault",
                "username": "ops",
                "url": "https://ops",
                "notes": "team login",
                "tags": ["ops"],
                "modified_ts": 100,
            },
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]
        scope_path = f"seed/{tmp_path.name}"
        mock_manager.vault.load_index.return_value = {
            "_system": {
                "index0": {
                    "canonical_views": {
                        f"recent_activity:{scope_path}": {
                            "view_id": f"recent_activity:{scope_path}",
                            "view_type": "recent_activity",
                            "scope_path": scope_path,
                            "source_checkpoint_ids": [],
                            "source_event_ids": [],
                            "data": {
                                "items": [
                                    {"subject_id": "1", "event_type": "entry_modified"}
                                ]
                            },
                            "modified_ts": 1,
                            "view_hash": "abc",
                        }
                    }
                }
            }
        }

        results = service.search("references plan", mode="keyword")

        assert [row["entry_id"] for row in results] == [1]
        assert results[0]["scope_path"] == scope_path
        assert results[0]["score_breakdown"]["lexical"] > 0
        assert "planning" in results[0]["tags"]
        assert results[0]["linked_hits"][0]["relation"] == "references"
        assert results[0]["excerpt"].startswith("SeedPass atlas")

    def test_linked_neighbors_and_relation_summary(
        self, service, mock_manager, tmp_path
    ):
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Project Plan", None, None, False, EntryType.DOCUMENT),
            (2, "Ops Vault", "ops", "https://ops", False, EntryType.PASSWORD),
            (3, "Runbook", None, None, False, EntryType.DOCUMENT),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Project Plan",
                "links": [{"target_id": 2, "relation": "references"}],
            },
            2: {
                "id": 2,
                "kind": "password",
                "label": "Ops Vault",
                "username": "ops",
                "url": "https://ops",
            },
            3: {
                "id": 3,
                "kind": "document",
                "label": "Runbook",
                "links": [{"target_id": 1, "relation": "depends_on"}],
            },
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]

        neighbors = service.linked_neighbors(1)
        summary = service.relation_summary(1)

        assert neighbors == [
            {
                "entry_id": 3,
                "label": "Runbook",
                "kind": "document",
                "scope_path": f"seed/{tmp_path.name}",
                "archived": False,
                "direction": "incoming",
                "relation": "depends_on",
                "note": "",
                "tags": [],
                "meta": "",
            },
            {
                "entry_id": 2,
                "label": "Ops Vault",
                "kind": "password",
                "scope_path": f"seed/{tmp_path.name}",
                "archived": False,
                "direction": "outgoing",
                "relation": "references",
                "note": "",
                "tags": [],
                "meta": "ops",
            },
        ]
        assert summary == {
            "incoming": {"depends_on": 1},
            "outgoing": {"references": 1},
            "combined": {"depends_on": 1, "references": 1},
        }

    @patch("seedpass.core.api.SemanticIndexService.search")
    def test_hybrid_search_combines_semantic_and_filters(
        self, semantic_search, service, mock_manager, tmp_path
    ):
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.config_manager.get_semantic_index_enabled.return_value = True
        mock_manager.config_manager.get_semantic_search_mode.return_value = "hybrid"
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Alpha Notes", None, None, False, EntryType.DOCUMENT),
            (2, "Beta Notes", None, None, True, EntryType.DOCUMENT),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Alpha Notes",
                "content": "hello atlas world",
                "tags": ["alpha"],
                "modified_ts": 100,
            },
            2: {
                "id": 2,
                "kind": "document",
                "label": "Beta Notes",
                "content": "hello beta world",
                "tags": ["beta"],
                "archived": True,
                "modified_ts": 200,
            },
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]
        mock_manager.vault.load_index.return_value = {"_system": {"index0": {}}}
        semantic_search.return_value = [
            {
                "entry_id": 1,
                "kind": "document",
                "label": "Alpha Notes",
                "score": 0.9,
                "excerpt": "hello atlas world",
            }
        ]

        results = service.search(
            "hello alpha atlas",
            mode="hybrid",
            include_archived=False,
            tags=["alpha"],
        )

        assert [row["entry_id"] for row in results] == [1]
        assert results[0]["score_breakdown"]["semantic"] == 0.9
        assert "semantic_match" in results[0]["match_reasons"]
        assert "tag:alpha" in results[0]["match_reasons"]

    def test_sort_by_modified_desc_without_query(self, service, mock_manager, tmp_path):
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Older", None, None, False, EntryType.DOCUMENT),
            (2, "Newer", None, None, False, EntryType.DOCUMENT),
        ]
        entries = {
            1: {"id": 1, "kind": "document", "label": "Older", "modified_ts": 100},
            2: {"id": 2, "kind": "document", "label": "Newer", "modified_ts": 200},
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]
        mock_manager.vault.load_index.return_value = {"_system": {"index0": {}}}

        results = service.search("", sort="modified_desc")

        assert [row["entry_id"] for row in results[:2]] == [2, 1]


class TestEntryServiceExtended:
    @pytest.fixture
    def service(self, mock_manager):
        return EntryService(mock_manager)

    def test_search_entries_include_archived(self, service, mock_manager):
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "active", None, None, False, EntryType.PASSWORD),
            (2, "archived", None, None, True, EntryType.PASSWORD),
        ]
        results = service.search_entries("q", include_archived=True)
        assert [row[0] for row in results] == [1, 2]

    def test_search_entries_archived_only(self, service, mock_manager):
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "active", None, None, False, EntryType.PASSWORD),
            (2, "archived", None, None, True, EntryType.PASSWORD),
        ]
        results = service.search_entries("q", include_archived=True, archived_only=True)
        assert [row[0] for row in results] == [2]

    def test_retrieve_entry(self, service, mock_manager):
        mock_entry = {"id": 1, "label": "test"}
        mock_manager.entry_manager.retrieve_entry.return_value = mock_entry
        entry = service.retrieve_entry(1)

        mock_manager.entry_manager.retrieve_entry.assert_called_once_with(1)
        assert entry == mock_entry

    def test_generate_password_default(self, service, mock_manager):
        # Case where _generate_password_for_entry is not available
        del mock_manager._generate_password_for_entry
        mock_manager.password_generator.generate_password.return_value = "pass123"
        mock_manager.entry_manager.retrieve_entry.return_value = {}

        password = service.generate_password(10, 1)

        mock_manager.password_generator.generate_password.assert_called_once_with(10, 1)
        assert password == "pass123"

    def test_generate_password_custom(self, service, mock_manager):
        # Case where _generate_password_for_entry is available
        mock_manager._generate_password_for_entry = MagicMock(return_value="custom123")
        mock_manager.entry_manager.retrieve_entry.return_value = {"policy": {}}

        password = service.generate_password(10, 1)

        mock_manager._generate_password_for_entry.assert_called_once()
        assert password == "custom123"

    def test_get_totp_code(self, service, mock_manager):
        mock_manager.KEY_TOTP_DET = b"key"
        mock_manager.entry_manager.get_totp_code.return_value = "123456"

        code = service.get_totp_code(1)

        mock_manager.entry_manager.get_totp_code.assert_called_once_with(1, b"key")
        assert code == "123456"

    def test_get_seed_phrase(self, service, mock_manager):
        mock_manager.entry_manager.get_seed_phrase.return_value = "seed words"
        phrase = service.get_seed_phrase(7)
        mock_manager.entry_manager.get_seed_phrase.assert_called_once_with(
            7, mock_manager.parent_seed
        )
        assert phrase == "seed words"

    def test_get_managed_account_seed(self, service, mock_manager):
        mock_manager.entry_manager.get_managed_account_seed.return_value = (
            "managed words"
        )
        phrase = service.get_managed_account_seed(8)
        mock_manager.entry_manager.get_managed_account_seed.assert_called_once_with(
            8, mock_manager.parent_seed
        )
        assert phrase == "managed words"

    def test_get_ssh_key_pair(self, service, mock_manager):
        mock_manager.entry_manager.get_ssh_key_pair.return_value = ("priv", "pub")
        result = service.get_ssh_key_pair(3)
        mock_manager.entry_manager.get_ssh_key_pair.assert_called_once_with(
            3, mock_manager.parent_seed
        )
        assert result == ("priv", "pub")

    def test_get_pgp_key(self, service, mock_manager):
        mock_manager.entry_manager.get_pgp_key.return_value = ("priv", "pub", "fp")
        result = service.get_pgp_key(4)
        mock_manager.entry_manager.get_pgp_key.assert_called_once_with(
            4, mock_manager.parent_seed
        )
        assert result == ("priv", "pub", "fp")

    def test_get_nostr_key_pair(self, service, mock_manager):
        mock_manager.entry_manager.get_nostr_key_pair.return_value = ("npub", "nsec")
        result = service.get_nostr_key_pair(5)
        mock_manager.entry_manager.get_nostr_key_pair.assert_called_once_with(
            5, mock_manager.parent_seed
        )
        assert result == ("npub", "nsec")

    def test_get_secret_mode_enabled(self, service, mock_manager):
        mock_manager.config_manager.get_secret_mode_enabled.return_value = True
        assert service.get_secret_mode_enabled() is True

    def test_get_clipboard_clear_delay(self, service, mock_manager):
        mock_manager.config_manager.get_clipboard_clear_delay.return_value = 40
        assert service.get_clipboard_clear_delay() == 40

    def test_copy_to_clipboard(self, service, mock_manager):
        mock_manager.config_manager.get_clipboard_clear_delay.return_value = 35
        with patch("seedpass.core.api.copy_to_clipboard", return_value=True) as patched:
            assert service.copy_to_clipboard("secret-value") is True
            patched.assert_called_once_with("secret-value", 35)

    def test_add_entry(self, service, mock_manager):
        mock_manager.entry_manager.add_entry.return_value = 1

        idx = service.add_entry("label", 12, "user", "url")

        mock_manager.entry_manager.add_entry.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 1

    def test_add_totp(self, service, mock_manager):
        mock_manager.entry_manager.add_totp.return_value = "otpauth://..."

        uri = service.add_totp("label")

        mock_manager.entry_manager.add_totp.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert uri == "otpauth://..."

    def test_add_ssh_key(self, service, mock_manager):
        mock_manager.entry_manager.add_ssh_key.return_value = 2

        idx = service.add_ssh_key("label")

        mock_manager.entry_manager.add_ssh_key.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 2

    def test_add_pgp_key(self, service, mock_manager):
        mock_manager.entry_manager.add_pgp_key.return_value = 3

        idx = service.add_pgp_key("label")

        mock_manager.entry_manager.add_pgp_key.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 3

    def test_add_nostr_key(self, service, mock_manager):
        mock_manager.entry_manager.add_nostr_key.return_value = 4

        idx = service.add_nostr_key("label")

        mock_manager.entry_manager.add_nostr_key.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 4

    def test_add_seed(self, service, mock_manager):
        mock_manager.entry_manager.add_seed.return_value = 5

        idx = service.add_seed("label")

        mock_manager.entry_manager.add_seed.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 5

    def test_add_key_value(self, service, mock_manager):
        mock_manager.entry_manager.add_key_value.return_value = 6

        idx = service.add_key_value("label", "k", "v")

        mock_manager.entry_manager.add_key_value.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 6

    def test_add_managed_account(self, service, mock_manager):
        mock_manager.entry_manager.add_managed_account.return_value = 7

        idx = service.add_managed_account("label")

        mock_manager.entry_manager.add_managed_account.assert_called_once()
        mock_manager.start_background_vault_sync.assert_called_once()
        assert idx == 7

    def test_modify_entry(self, service, mock_manager):
        service.modify_entry(1, label="new_label")

        mock_manager.entry_manager.modify_entry.assert_called_once_with(
            1,
            username=None,
            url=None,
            notes=None,
            label="new_label",
            period=None,
            digits=None,
            key=None,
            value=None,
            content=None,
            file_type=None,
            custom_fields=None,
            tags=None,
            links=None,
            archived=None,
        )
        mock_manager.start_background_vault_sync.assert_called_once()

    def test_archive_entry(self, service, mock_manager):
        service.archive_entry(1)

        mock_manager.entry_manager.archive_entry.assert_called_once_with(1)
        mock_manager.start_background_vault_sync.assert_called_once()

    def test_restore_entry(self, service, mock_manager):
        service.restore_entry(1)

        mock_manager.entry_manager.restore_entry.assert_called_once_with(1)
        mock_manager.start_background_vault_sync.assert_called_once()

    def test_export_totp_entries(self, service, mock_manager):
        mock_manager.entry_manager.export_totp_entries.return_value = {}

        result = service.export_totp_entries()

        mock_manager.entry_manager.export_totp_entries.assert_called_once()
        assert result == {}

    def test_display_totp_codes(self, service, mock_manager):
        service.display_totp_codes()
        mock_manager.handle_display_totp_codes.assert_called_once()

    def test_load_managed_account(self, service, mock_manager):
        service.load_managed_account(7)
        mock_manager.load_managed_account.assert_called_once_with(7)

    def test_exit_managed_account(self, service, mock_manager):
        service.exit_managed_account()
        mock_manager.exit_managed_account.assert_called_once()


class TestSearchServiceGraphTraversal:
    """multi_hop_neighbors, filtered_neighbors and graph_pivot_results.

    These three are the traversal behind atlas pivoting, and they arrived with
    the graph feature almost entirely untested — between them roughly 240 of
    the 269 uncovered lines in this module, which is what put
    seedpass/core/api.py under its coverage gate.

    They are tested against their documented contracts (hop numbering, path
    recording, shortest-path retention, the stated pivot scoring) rather than
    against whatever they happen to return, so a test failing here means the
    documented behaviour changed.
    """

    @pytest.fixture
    def service(self, mock_manager):
        return SearchService(mock_manager)

    @pytest.fixture
    def graph(self, mock_manager, tmp_path):
        """A small graph: 1 -> 2 -> 3, with archived 4 -> 1.

        1 "Project Plan"  (document) --references--> 2
        2 "Ops Vault"     (password) --depends_on--> 3
        3 "Runbook"       (document)
        4 "Old Note"      (document, archived) --mentions--> 1
        """
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Project Plan", None, None, False, EntryType.DOCUMENT),
            (2, "Ops Vault", "ops", "https://ops", False, EntryType.PASSWORD),
            (3, "Runbook", None, None, False, EntryType.DOCUMENT),
            (4, "Old Note", None, None, True, EntryType.DOCUMENT),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Project Plan",
                "links": [{"target_id": 2, "relation": "references"}],
            },
            2: {
                "id": 2,
                "kind": "password",
                "label": "Ops Vault",
                "username": "ops",
                "url": "https://ops",
                "links": [{"target_id": 3, "relation": "depends_on"}],
            },
            3: {"id": 3, "kind": "document", "label": "Runbook"},
            4: {
                "id": 4,
                "kind": "document",
                "label": "Old Note",
                "archived": True,
                "links": [{"target_id": 1, "relation": "mentions"}],
            },
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]
        return f"seed/{tmp_path.name}"

    # ------------------------------------------------------------ multi-hop

    def test_reaches_two_hops_and_records_hop_and_path(self, service, graph):
        rows = service.multi_hop_neighbors(1, hops=2, direction="outgoing")

        assert [(r["entry_id"], r["hop"]) for r in rows] == [(2, 1), (3, 2)]
        # `path` is the route taken, origin first — what a UI draws as a trail.
        assert rows[0]["path"] == [1, 2]
        assert rows[1]["path"] == [1, 2, 3]
        assert rows[0]["relation"] == "references"
        assert rows[1]["relation"] == "depends_on"
        assert rows[0]["scope_path"] == graph

    def test_hops_bounds_the_walk(self, service, graph):
        # hops=1 must not reach 3, which is only reachable through 2.
        rows = service.multi_hop_neighbors(1, hops=1, direction="outgoing")
        assert [r["entry_id"] for r in rows] == [2]

    def test_keeps_the_shortest_path_when_an_entry_is_reachable_twice(
        self, service, mock_manager, tmp_path
    ):
        # 1 -> 2 -> 3 and also 1 -> 3 directly. 3 must come back as hop 1, not
        # hop 2: "when the same entry is reachable via multiple paths only the
        # shortest-hop path is retained".
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "Origin", None, None, False, EntryType.DOCUMENT),
            (2, "Middle", None, None, False, EntryType.DOCUMENT),
            (3, "Target", None, None, False, EntryType.DOCUMENT),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Origin",
                "links": [
                    {"target_id": 2, "relation": "references"},
                    {"target_id": 3, "relation": "references"},
                ],
            },
            2: {
                "id": 2,
                "kind": "document",
                "label": "Middle",
                "links": [{"target_id": 3, "relation": "depends_on"}],
            },
            3: {"id": 3, "kind": "document", "label": "Target"},
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]

        rows = service.multi_hop_neighbors(1, hops=3, direction="outgoing")
        by_id = {r["entry_id"]: r for r in rows}
        assert by_id[3]["hop"] == 1
        assert by_id[3]["path"] == [1, 3]

    def test_a_cycle_terminates(self, service, mock_manager, tmp_path):
        # 1 -> 2 -> 1. Without the path check this walks forever; the origin is
        # also never returned as its own neighbor.
        mock_manager.fingerprint_dir = tmp_path
        mock_manager.entry_manager.search_entries.return_value = [
            (1, "A", None, None, False, EntryType.DOCUMENT),
            (2, "B", None, None, False, EntryType.DOCUMENT),
        ]
        entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "A",
                "links": [{"target_id": 2, "relation": "references"}],
            },
            2: {
                "id": 2,
                "kind": "document",
                "label": "B",
                "links": [{"target_id": 1, "relation": "references"}],
            },
        }
        mock_manager.entry_manager.retrieve_entry.side_effect = lambda eid: entries[eid]

        rows = service.multi_hop_neighbors(1, hops=5, direction="outgoing")
        assert [r["entry_id"] for r in rows] == [2]

    def test_direction_selects_which_edges_are_followed(self, service, graph):
        incoming = service.multi_hop_neighbors(1, hops=1, direction="incoming")
        assert [(r["entry_id"], r["direction"]) for r in incoming] == [(4, "incoming")]
        assert incoming[0]["relation"] == "mentions"

        both = service.multi_hop_neighbors(1, hops=1, direction="both")
        assert sorted(r["entry_id"] for r in both) == [2, 4]

        # An unrecognised direction falls back to "both" rather than refusing
        # or returning nothing.
        assert sorted(
            r["entry_id"]
            for r in service.multi_hop_neighbors(1, hops=1, direction="sideways")
        ) == [2, 4]

    def test_include_archived_false_drops_the_archived_neighbor(self, service, graph):
        rows = service.multi_hop_neighbors(
            1, hops=1, direction="both", include_archived=False
        )
        assert [r["entry_id"] for r in rows] == [2]

    def test_relation_filter_selects_edges_by_name(self, service, graph):
        rows = service.multi_hop_neighbors(
            1, hops=2, direction="outgoing", relation="references"
        )
        # Only the `references` edge is followed, so 3 — reached by
        # `depends_on` — is not present.
        assert [r["entry_id"] for r in rows] == [2]

    def test_kind_filter_also_prunes_the_walk(self, service, graph):
        # Worth pinning because it is surprising: `kinds` filters the RESULTS,
        # and because the filter is applied before the neighbor is queued it
        # also prunes TRAVERSAL THROUGH that neighbor. Entry 3 is a document
        # and would satisfy the filter, but it is only reachable through 2,
        # which is a password and is therefore never stepped through.
        rows = service.multi_hop_neighbors(
            1, hops=2, direction="outgoing", kinds=["document"]
        )
        assert rows == []

        # Filtering to the kind that IS on the path returns it.
        rows = service.multi_hop_neighbors(
            1, hops=2, direction="outgoing", kinds=["password"]
        )
        assert [r["entry_id"] for r in rows] == [2]

    def test_limit_caps_results_and_never_returns_nothing(self, service, graph):
        assert (
            len(service.multi_hop_neighbors(1, hops=2, direction="outgoing", limit=1))
            == 1
        )
        # `max(1, limit)`: a limit of 0 yields one row rather than an empty
        # list, which would otherwise read as "no neighbors".
        assert (
            len(service.multi_hop_neighbors(1, hops=2, direction="outgoing", limit=0))
            == 1
        )

    def test_a_missing_or_invalid_origin_returns_nothing(self, service, graph):
        assert service.multi_hop_neighbors(0) == []
        assert service.multi_hop_neighbors(-1) == []

    # ------------------------------------------------------- direct filtered

    def test_filtered_neighbors_selects_by_kind(self, service, graph):
        assert [
            r["entry_id"] for r in service.filtered_neighbors(1, kinds=["password"])
        ] == [2]
        # Direct neighbors only, so the archived document 4 appears while the
        # two-hop document 3 does not.
        assert [
            r["entry_id"] for r in service.filtered_neighbors(1, kinds=["document"])
        ] == [4]

    def test_filtered_neighbors_without_kinds_is_every_direct_neighbor(
        self, service, graph
    ):
        assert sorted(r["entry_id"] for r in service.filtered_neighbors(1)) == [2, 4]
        assert sorted(
            r["entry_id"] for r in service.filtered_neighbors(1, kinds=[])
        ) == [2, 4]

    def test_filtered_neighbors_honours_include_archived(self, service, graph):
        rows = service.filtered_neighbors(1, kinds=["document"], include_archived=False)
        assert rows == []

    # ------------------------------------------------------------ graph pivot

    def test_pivot_scores_outgoing_above_incoming(self, service, graph):
        rows = service.graph_pivot_results(1)
        by_id = {r["entry_id"]: r for r in rows}

        # Documented scoring: a direct outgoing link is 1.0, incoming takes a
        # 0.1 direction penalty. Both are hop 1 here, so no hop penalty.
        assert by_id[2]["score"] == 1.0
        assert by_id[4]["score"] == 0.9
        # Highest score first — this is what orders the pivot list in the UI.
        assert [r["entry_id"] for r in rows] == [2, 4]

    def test_pivot_results_are_search_result_shaped(self, service, graph):
        rows = service.graph_pivot_results(1, pivot_scope="atlas/plan")
        row = next(r for r in rows if r["entry_id"] == 2)

        # The point of this method is that graph hits are indistinguishable in
        # SHAPE from search hits, so any surface consuming search output can
        # consume these.
        for field in (
            "entry_id",
            "label",
            "kind",
            "scope_path",
            "archived",
            "score",
            "score_breakdown",
            "match_reasons",
            "excerpt",
            "linked_hits",
            "tags",
            "modified_ts",
            "meta",
        ):
            assert field in row

        assert row["match_reasons"] == sorted(
            {
                "graph_pivot",
                "relation:references",
                "direction:outgoing",
                "atlas:atlas/plan",
            }
        )
        # The whole score is structural — nothing here came from text matching.
        assert row["score_breakdown"]["structural"] == row["score"]
        assert row["score_breakdown"]["lexical"] == 0.0
        assert row["score_breakdown"]["semantic"] == 0.0
        # linked_hits points back at the pivot, not at the neighbor.
        assert row["linked_hits"] == [{"target_id": 1, "relation": "references"}]
        # Direction is legible in the meta string: -> out, <- in.
        assert row["meta"].startswith("->[references]")
        assert "atlas:atlas/plan" in row["meta"]
        assert next(r for r in rows if r["entry_id"] == 4)["meta"].startswith(
            "<-[mentions]"
        )

    def test_pivot_never_puts_a_password_in_an_excerpt(self, service, graph):
        # Entry 2 is a password. Excerpts are rendered straight into result
        # lists, so secret-bearing kinds must come back empty.
        row = next(r for r in service.graph_pivot_results(1) if r["entry_id"] == 2)
        assert row["excerpt"] == ""

    def test_pivot_honours_include_archived_and_limit(self, service, graph):
        assert [
            r["entry_id"]
            for r in service.graph_pivot_results(1, include_archived=False)
        ] == [2]
        assert len(service.graph_pivot_results(1, limit=1)) == 1

    def test_pivot_on_a_missing_origin_returns_nothing(self, service, graph):
        assert service.graph_pivot_results(0) == []
        assert service.graph_pivot_results(-5) == []


class TestSearchServiceExcerpts:
    """What text from an entry is allowed to reach a result list.

    `_safe_excerpt` picks the field shown under a search hit, and
    `_SECRET_EXCERPT_KINDS` names the kinds whose excerpt is suppressed
    entirely by the callers. Between them they decide what a search result can
    disclose, which makes the per-kind field choice worth pinning rather than
    inferring from whichever kind a test happened to use.
    """

    @pytest.fixture
    def service(self, mock_manager):
        return SearchService(mock_manager)

    def test_excerpt_field_per_kind(self, service):
        excerpt = SearchService._safe_excerpt
        # notes wins for every kind, when present.
        assert excerpt({"notes": "a note", "content": "body"}, "document") == "a note"
        # Otherwise the kind decides which field is legible.
        assert excerpt({"content": "body text"}, "document") == "body text"
        assert excerpt({"content": "body text"}, "note") == "body text"
        assert excerpt({"username": "alice", "url": "https://x"}, "password") == "alice"
        assert excerpt({"url": "https://x"}, "password") == "https://x"
        assert excerpt({"key": "API_TOKEN"}, "key_value") == "API_TOKEN"
        assert excerpt({"issuer": "GitHub"}, "totp") == "GitHub"
        assert excerpt({"npub": "npub1abc"}, "nostr") == "npub1abc"
        assert excerpt({"fingerprint": "AA:BB"}, "ssh") == "AA:BB"
        assert excerpt({"fingerprint": "AA:BB"}, "pgp") == "AA:BB"
        # A kind with no configured field discloses nothing beyond notes.
        assert excerpt({"content": "body"}, "seed") == ""
        assert excerpt({}, "document") == ""

    def test_excerpt_never_reaches_a_secret_field(self, service):
        # The named fields are metadata. A password, a seed phrase or a private
        # key must not be reachable through this function whatever the kind.
        secretish = {
            "password": "hunter2",
            "value": "s3cret",
            "seed": "abandon abandon abandon",
            "private_key": "-----BEGIN-----",
            "secret": "JBSWY3DPEHPK3PXP",
        }
        for kind in [
            "password",
            "stored_password",
            "totp",
            "seed",
            "managed_account",
            "ssh",
            "pgp",
            "nostr",
            "key_value",
            "document",
            "note",
        ]:
            assert SearchService._safe_excerpt(dict(secretish), kind) == ""

    def test_excerpt_is_bounded(self, service):
        # Excerpts are rendered into lists; an unbounded one is a UI hazard and
        # a way to push a lot of vault content through a narrow surface.
        assert (
            len(SearchService._safe_excerpt({"notes": "x" * 1000}, "document")) == 220
        )

    def test_secret_bearing_kinds_are_declared(self, service):
        # Callers suppress the excerpt entirely for these. If a new
        # secret-bearing kind is added and not listed here, its metadata starts
        # appearing in result lists.
        assert SearchService._SECRET_EXCERPT_KINDS == {
            "password",
            "stored_password",
            "totp",
            "seed",
            "managed_account",
            "ssh",
            "pgp",
            "nostr",
        }

    def test_meta_field_precedence(self, service):
        meta = SearchService._meta
        assert meta({"username": "alice", "url": "https://x"}, "password") == "alice"
        assert meta({"url": "https://x"}, "password") == "https://x"
        assert meta({"key": "API_TOKEN"}, "key_value") == "API_TOKEN"
        assert meta({"file_type": "pdf"}, "document") == "pdf"
        assert meta({}, "managed_account") == "managed"
        assert meta({}, "document") == ""

    def test_custom_field_text_collects_names_and_values(self, service):
        text = SearchService._custom_field_text
        assert (
            text({"custom_fields": [{"name": "env", "value": "prod"}]}) == "env\nprod"
        )
        # Non-list and non-dict members are ignored rather than raising: this
        # reads whatever is in the vault, including entries other tools wrote.
        assert text({"custom_fields": "not-a-list"}) == ""
        assert text({"custom_fields": [None, 5, {"label": "team"}]}) == "team"
        assert text({}) == ""


class TestConfigService:
    @pytest.fixture
    def service(self, mock_manager):
        return ConfigService(mock_manager)

    def test_get(self, service, mock_manager):
        mock_manager.config_manager.load_config.return_value = {"key": "value"}
        val = service.get("key")

        mock_manager.config_manager.load_config.assert_called_once_with(
            require_pin=False
        )
        assert val == "value"

    def test_set_simple(self, service, mock_manager):
        service.set("inactivity_timeout", "10")
        mock_manager.config_manager.set_inactivity_timeout.assert_called_once_with(10.0)

    def test_set_bool(self, service, mock_manager):
        service.set("secret_mode_enabled", "true")
        mock_manager.config_manager.set_secret_mode_enabled.assert_called_once_with(
            True
        )

    def test_set_relays(self, service, mock_manager):
        # relays setter logic: ("set_relays", lambda v: (v, {"require_pin": False})),
        # but the lambda returns a tuple (arg, kwargs)
        # and then getattr(cfg, method_name)(arg, **kwargs) is called.
        # Wait, the lambda returns (v, {"require_pin": False})
        # So arg is v, kwargs is {"require_pin": False}

        service.set("relays", ["r1"])
        mock_manager.config_manager.set_relays.assert_called_once_with(
            ["r1"], require_pin=False
        )

    def test_set_invalid_key(self, service, mock_manager):
        with pytest.raises(KeyError):
            service.set("invalid_key", "val")

    def test_get_secret_mode_enabled(self, service, mock_manager):
        mock_manager.config_manager.get_secret_mode_enabled.return_value = True
        assert service.get_secret_mode_enabled() is True

    def test_get_clipboard_clear_delay(self, service, mock_manager):
        mock_manager.config_manager.get_clipboard_clear_delay.return_value = 45
        assert service.get_clipboard_clear_delay() == 45

    def test_set_secret_mode(self, service, mock_manager):
        service.set_secret_mode(True, 30)

        mock_manager.config_manager.set_secret_mode_enabled.assert_called_once_with(
            True
        )
        mock_manager.config_manager.set_clipboard_clear_delay.assert_called_once_with(
            30
        )
        assert mock_manager.secret_mode_enabled is True
        assert mock_manager.clipboard_clear_delay == 30

    def test_get_offline_mode(self, service, mock_manager):
        mock_manager.config_manager.get_offline_mode.return_value = False
        assert service.get_offline_mode() is False

    def test_set_offline_mode(self, service, mock_manager):
        service.set_offline_mode(True)

        mock_manager.config_manager.set_offline_mode.assert_called_once_with(True)
        assert mock_manager.offline_mode is True


class TestUtilityService:
    @pytest.fixture
    def service(self, mock_manager):
        return UtilityService(mock_manager)

    def test_generate_password(self, service, mock_manager):
        mock_manager.password_generator.generate_password.return_value = "pw"

        # Mock policy with a real dataclass
        base_policy = MockPolicy(include_special_chars=False, min_uppercase=0)
        mock_manager.password_generator.policy = base_policy

        result = service.generate_password(
            10, include_special_chars=True, min_uppercase=5
        )

        mock_manager.password_generator.generate_password.assert_called_once_with(10)
        assert result == "pw"

        # Verify policy was restored
        assert mock_manager.password_generator.policy == base_policy

    def test_verify_checksum(self, service, mock_manager):
        service.verify_checksum()
        mock_manager.handle_verify_checksum.assert_called_once()

    def test_update_checksum(self, service, mock_manager):
        service.update_checksum()
        mock_manager.handle_update_script_checksum.assert_called_once()


class TestNostrService:
    @pytest.fixture
    def service(self, mock_manager):
        return NostrService(mock_manager)

    def test_get_pubkey(self, service, mock_manager):
        mock_manager.nostr_client.key_manager.get_npub.return_value = "npub1..."
        assert service.get_pubkey() == "npub1..."

    def test_list_relays(self, service, mock_manager):
        mock_manager.state_manager.list_relays.return_value = ["r1"]
        assert service.list_relays() == ["r1"]

    def test_add_relay(self, service, mock_manager):
        mock_manager.state_manager.list_relays.return_value = ["r1", "r2"]
        service.add_relay("r2")

        mock_manager.state_manager.add_relay.assert_called_once_with("r2")
        assert mock_manager.nostr_client.relays == ["r1", "r2"]

    def test_remove_relay(self, service, mock_manager):
        mock_manager.state_manager.list_relays.return_value = []
        service.remove_relay(0)

        mock_manager.state_manager.remove_relay.assert_called_once_with(0)
        assert mock_manager.nostr_client.relays == []

    def test_reset_sync_state(self, service, mock_manager):
        mock_manager.state_manager.state = {"nostr_account_idx": 3}
        idx = service.reset_sync_state()

        mock_manager.state_manager.update_state.assert_called_once_with(
            manifest_id=None, delta_since=0, last_sync_ts=0
        )
        assert idx == 3
        assert mock_manager.nostr_account_idx == 3
        assert mock_manager.manifest_id is None
        assert mock_manager.delta_since == 0
        assert mock_manager.last_sync_ts == 0

    def test_start_fresh_namespace(self, service, mock_manager):
        mock_manager.state_manager.state = {"nostr_account_idx": 4}

        next_idx = service.start_fresh_namespace()

        mock_manager.state_manager.update_state.assert_called_once_with(
            manifest_id=None,
            delta_since=0,
            last_sync_ts=0,
            nostr_account_idx=5,
        )
        mock_manager._initialize_nostr_client.assert_called_once()
        assert next_idx == 5
        assert mock_manager.nostr_account_idx == 5
