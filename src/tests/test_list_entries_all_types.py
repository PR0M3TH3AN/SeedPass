from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from typer.testing import CliRunner

from seedpass.cli import app as cli_app
from seedpass.cli import entry as entry_cli
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def _setup_manager(tmp_path: Path) -> tuple[PasswordManager, EntryManager]:
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


def _create_all_entries(em: EntryManager) -> None:
    em.add_entry("pw", 8)
    em.add_totp("totp", TEST_SEED)
    em.add_ssh_key("ssh", TEST_SEED)
    em.add_seed("seed", TEST_SEED, words_num=12)
    em.add_nostr_key("nostr", TEST_SEED)
    em.add_pgp_key("pgp", TEST_SEED)
    em.add_key_value("kv", "k", "v")
    em.add_managed_account("acct", TEST_SEED)


def test_cli_list_all_types(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, em = _setup_manager(tmp_path)
        _create_all_entries(em)

        def fake_get_entry_service(_ctx):
            return SimpleNamespace(
                list_entries=lambda sort_by, filter_kinds, include_archived: pm.entry_manager.list_entries(
                    sort_by=sort_by,
                    filter_kinds=filter_kinds,
                    include_archived=include_archived,
                )
            )

        monkeypatch.setattr(entry_cli, "_get_entry_service", fake_get_entry_service)

        runner = CliRunner()
        result = runner.invoke(cli_app, ["entry", "list"])
        assert result.exit_code == 0
        out = result.stdout
        for label in ["pw", "totp", "ssh", "seed", "nostr", "pgp", "kv", "acct"]:
            assert label in out


def test_menu_list_all_types(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, em = _setup_manager(tmp_path)
        _create_all_entries(em)

        inputs = iter(["1", "", ""])  # choose All then exit
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

        pm.handle_list_entries()
        out = capsys.readouterr().out
        for label in ["pw", "totp", "ssh", "seed", "nostr", "pgp", "kv", "acct"]:
            assert label in out
