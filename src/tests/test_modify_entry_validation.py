import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

# Add source directory to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.entry_types import EntryType
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


@pytest.fixture
def entry_manager():
    """Fixture to set up an EntryManager with a temporary vault."""
    with TemporaryDirectory() as tmpdir:
        vault, _ = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        yield EntryManager(vault, backup_mgr)


@pytest.mark.parametrize(
    "entry_type, setup_func, invalid_kwargs, expected_msg_part",
    [
        (
            EntryType.PASSWORD,
            lambda em: em.add_entry("Pass", 12),
            {"period": 30},  # 'period' is for TOTP, not Password
            "does not support fields: period",
        ),
        (
            EntryType.TOTP,
            lambda em: em.add_totp("TOTP", TEST_SEED),
            {"username": "user"},  # 'username' is for Password, not TOTP
            "does not support fields: username",
        ),
        (
            EntryType.KEY_VALUE,
            lambda em: em.add_key_value("KV", "k", "v"),
            {"url": "http://example.com"},  # 'url' is for Password, not KeyValue
            "does not support fields: url",
        ),
        (
            EntryType.MANAGED_ACCOUNT,
            lambda em: em.add_managed_account("MA", TEST_SEED),
            {"key": "new_key"},  # 'key' is for KeyValue, not ManagedAccount
            "does not support fields: key",
        ),
        (
            EntryType.SSH,
            lambda em: em.add_ssh_key("SSH", TEST_SEED),
            {"value": "some_val"},  # 'value' is for KeyValue/ManagedAccount, not SSH
            "does not support fields: value",
        ),
        (
            EntryType.PGP,
            lambda em: em.add_pgp_key("PGP", TEST_SEED),
            {"username": "pgp_user"},
            "does not support fields: username",
        ),
        (
            EntryType.NOSTR,
            lambda em: em.add_nostr_key("Nostr", TEST_SEED),
            {"period": 60},
            "does not support fields: period",
        ),
        (
            EntryType.SEED,
            lambda em: em.add_seed("Seed", TEST_SEED),
            {"url": "seed_url"},
            "does not support fields: url",
        ),
    ],
)
def test_modify_entry_invalid_fields(
    entry_manager, entry_type, setup_func, invalid_kwargs, expected_msg_part
):
    """Test that modify_entry raises ValueError for invalid fields based on EntryType."""
    # Setup entry
    if entry_type == EntryType.TOTP:
         # add_totp returns a URI string, need to fix the index manually or check implementation
         # Checking implementation: add_totp returns URI string, but index is predictable (0)
         # However, we should verify the index.
         # For simplicity, we assume index 0 as it's the first entry.
         setup_func(entry_manager)
         index = 0
    elif entry_type == EntryType.PASSWORD:
         index = setup_func(entry_manager)
    else:
         index = setup_func(entry_manager)

    # Verify entry exists and has correct type
    entry = entry_manager.retrieve_entry(index)
    assert entry is not None
    # Handle legacy 'kind' vs 'type'
    actual_type = entry.get("type", entry.get("kind"))
    assert actual_type == entry_type.value

    # Attempt modification with invalid fields
    with pytest.raises(ValueError) as excinfo:
        entry_manager.modify_entry(index, **invalid_kwargs)

    assert expected_msg_part in str(excinfo.value)
