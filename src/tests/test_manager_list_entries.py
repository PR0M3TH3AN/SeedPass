from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


def test_handle_list_entries(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path

        entry_mgr.add_totp("Example", TEST_SEED)
        entry_mgr.add_entry("example.com", 12)
        entry_mgr.add_key_value("API", "abc123")
        entry_mgr.add_managed_account("acct", TEST_SEED)

        inputs = iter(["1", ""])  # list all, then exit
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

        pm.handle_list_entries()
        out = capsys.readouterr().out
        assert "Example" in out
        assert "example.com" in out
        assert "API" in out
        assert "acct" in out


def test_list_entries_show_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.parent_seed = TEST_SEED
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False

        entry_mgr.add_totp("Example", TEST_SEED)
        entry_mgr.add_key_value("API", "val")
        entry_mgr.add_managed_account("acct", TEST_SEED)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 1
        )
        monkeypatch.setattr("password_manager.manager.time.sleep", lambda *a, **k: None)
        monkeypatch.setattr(
            "password_manager.manager.timed_input",
            lambda *a, **k: "b",
        )

        inputs = iter(["1", "0"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

        pm.handle_list_entries()
        out = capsys.readouterr().out
        assert "Label: Example" in out
        assert "Period: 30s" in out
        assert "API" in out
        assert "acct" in out


def test_show_entry_details_by_index(monkeypatch):
    """Ensure entry details screen triggers expected calls."""
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path

        index = entry_mgr.add_entry("example.com", 12)

        header_calls = []
        monkeypatch.setattr(
            "password_manager.manager.clear_header_with_notification",
            lambda *a, **k: header_calls.append(True),
        )

        call_order = []
        monkeypatch.setattr(
            pm,
            "display_entry_details",
            lambda *a, **k: call_order.append("display"),
        )
        monkeypatch.setattr(
            pm,
            "_entry_actions_menu",
            lambda *a, **k: call_order.append("actions"),
        )
        monkeypatch.setattr("password_manager.manager.pause", lambda *a, **k: None)
        monkeypatch.setattr(
            "password_manager.manager.confirm_action", lambda *a, **k: False
        )

        pm.show_entry_details_by_index(index)

        assert len(header_calls) == 1
        assert call_order == ["display", "actions"]


def _setup_manager(tmp_path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.parent_seed = TEST_SEED
    pm.nostr_client = SimpleNamespace()
    pm.fingerprint_dir = tmp_path
    pm.secret_mode_enabled = False
    return pm, entry_mgr


def _detail_common(monkeypatch, pm):
    monkeypatch.setattr(
        "password_manager.manager.clear_header_with_notification",
        lambda *a, **k: None,
    )
    monkeypatch.setattr("password_manager.manager.pause", lambda *a, **k: None)
    monkeypatch.setattr(
        "password_manager.manager.confirm_action", lambda *a, **k: False
    )
    called = []
    monkeypatch.setattr(pm, "_entry_actions_menu", lambda *a, **k: called.append(True))
    return called


def test_show_seed_entry_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, entry_mgr = _setup_manager(tmp_path)
        idx = entry_mgr.add_seed("seed", TEST_SEED, words_num=12)

        called = _detail_common(monkeypatch, pm)

        pm.show_entry_details_by_index(idx)
        out = capsys.readouterr().out
        assert "Type: Seed Phrase" in out
        assert "Label: seed" in out
        assert "Words: 12" in out
        assert f"Derivation Index: {idx}" in out
        assert called == [True]


def test_show_ssh_entry_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, entry_mgr = _setup_manager(tmp_path)
        idx = entry_mgr.add_ssh_key("ssh", TEST_SEED)

        called = _detail_common(monkeypatch, pm)

        pm.show_entry_details_by_index(idx)
        out = capsys.readouterr().out
        assert "Type: SSH Key" in out
        assert "Label: ssh" in out
        assert f"Derivation Index: {idx}" in out
        assert called == [True]


def test_show_pgp_entry_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, entry_mgr = _setup_manager(tmp_path)
        idx = entry_mgr.add_pgp_key("pgp", TEST_SEED, user_id="test")

        called = _detail_common(monkeypatch, pm)

        pm.show_entry_details_by_index(idx)
        out = capsys.readouterr().out
        assert "Type: PGP Key" in out
        assert "Label: pgp" in out
        assert "Key Type: ed25519" in out
        assert "User ID: test" in out
        assert f"Derivation Index: {idx}" in out
        assert called == [True]


def test_show_nostr_entry_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, entry_mgr = _setup_manager(tmp_path)
        idx = entry_mgr.add_nostr_key("nostr")

        called = _detail_common(monkeypatch, pm)

        pm.show_entry_details_by_index(idx)
        out = capsys.readouterr().out
        assert "Type: Nostr Key" in out
        assert "Label: nostr" in out
        assert f"Derivation Index: {idx}" in out
        assert called == [True]


def test_show_managed_account_entry_details(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, entry_mgr = _setup_manager(tmp_path)
        idx = entry_mgr.add_managed_account("acct", TEST_SEED)
        fp = entry_mgr.retrieve_entry(idx).get("fingerprint")

        called = _detail_common(monkeypatch, pm)

        pm.show_entry_details_by_index(idx)
        out = capsys.readouterr().out
        assert "Type: Managed Account" in out
        assert "Label: acct" in out
        assert f"Derivation Index: {idx}" in out
        assert "Words: 12" in out
        assert fp in out
        assert called == [True]
