import pytest
from pathlib import Path

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def setup_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    backup = BackupManager(tmp_path, cfg)
    return EntryManager(vault, backup)


def test_add_totp_invalid_secret(tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    with pytest.raises(ValueError):
        mgr.add_totp("bad", TEST_SEED, secret="notbase32!")


def test_add_ssh_key_validation_failure(monkeypatch, tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.entry_management.validate_ssh_key_pair", lambda p, q: False
    )
    with pytest.raises(ValueError):
        mgr.add_ssh_key("ssh", TEST_SEED)


def test_add_pgp_key_validation_failure(monkeypatch, tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.entry_management.validate_pgp_private_key", lambda p, q: False
    )
    with pytest.raises(ValueError):
        mgr.add_pgp_key("pgp", TEST_SEED, user_id="test")


def test_add_nostr_key_validation_failure(monkeypatch, tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.entry_management.validate_nostr_keys", lambda p, q: False
    )
    with pytest.raises(ValueError):
        mgr.add_nostr_key("nostr", TEST_SEED)


def test_add_seed_validation_failure(monkeypatch, tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.entry_management.validate_seed_phrase", lambda p: False
    )
    with pytest.raises(ValueError):
        mgr.add_seed("seed", TEST_SEED)


def test_add_managed_account_validation_failure(monkeypatch, tmp_path: Path):
    mgr = setup_mgr(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.entry_management.validate_seed_phrase", lambda p: False
    )
    with pytest.raises(ValueError):
        mgr.add_managed_account("acct", TEST_SEED)
