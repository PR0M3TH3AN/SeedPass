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
    ConfigService,
    UtilityService,
    NostrService,
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
