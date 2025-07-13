import re
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from typer.testing import CliRunner
from seedpass import cli
from password_manager.entry_types import EntryType


class DummyPM:
    def __init__(self):
        self.entry_manager = SimpleNamespace(
            list_entries=lambda sort_by="index", filter_kind=None, include_archived=False: [
                (1, "Label", "user", "url", False)
            ],
            search_entries=lambda q: [(1, "GitHub", "user", "", False)],
            retrieve_entry=lambda idx: {"type": EntryType.PASSWORD.value, "length": 8},
            get_totp_code=lambda idx, seed: "123456",
            add_entry=lambda label, length, username, url: 1,
            add_totp=lambda label, seed, index=None, secret=None, period=30, digits=6: "totp://",
            add_ssh_key=lambda label, seed, index=None, notes="": 2,
            add_pgp_key=lambda label, seed, index=None, key_type="ed25519", user_id="", notes="": 3,
            add_nostr_key=lambda label, index=None, notes="": 4,
            add_seed=lambda label, seed, index=None, words_num=24, notes="": 5,
            add_key_value=lambda label, value, notes="": 6,
            add_managed_account=lambda label, seed, index=None, notes="": 7,
            modify_entry=lambda *a, **kw: None,
            archive_entry=lambda i: None,
            restore_entry=lambda i: None,
            export_totp_entries=lambda seed: {"entries": []},
        )
        self.password_generator = SimpleNamespace(
            generate_password=lambda length, index=None: "pw"
        )
        self.parent_seed = "seed"
        self.handle_display_totp_codes = lambda: None
        self.handle_export_database = lambda path: None
        self.handle_import_database = lambda path: None
        self.change_password = lambda: None
        self.lock_vault = lambda: None
        self.get_profile_stats = lambda: {"n": 1}
        self.handle_backup_reveal_parent_seed = lambda path=None: None
        self.handle_verify_checksum = lambda: None
        self.handle_update_script_checksum = lambda: None
        self.add_new_fingerprint = lambda: None
        self.fingerprint_manager = SimpleNamespace(
            list_fingerprints=lambda: ["fp"], remove_fingerprint=lambda fp: None
        )
        self.nostr_client = SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "npub")
        )
        self.sync_vault = lambda: "event"
        self.config_manager = SimpleNamespace(
            load_config=lambda require_pin=False: {"inactivity_timeout": 30},
            set_inactivity_timeout=lambda v: None,
            set_kdf_iterations=lambda v: None,
            set_backup_interval=lambda v: None,
            set_secret_mode_enabled=lambda v: None,
            set_clipboard_clear_delay=lambda v: None,
            set_additional_backup_path=lambda v: None,
            set_relays=lambda v, require_pin=False: None,
            set_nostr_max_retries=lambda v: None,
            set_nostr_retry_delay=lambda v: None,
            set_offline_mode=lambda v: None,
            get_secret_mode_enabled=lambda: True,
            get_clipboard_clear_delay=lambda: 30,
            get_offline_mode=lambda: False,
        )
        self.secret_mode_enabled = True
        self.clipboard_clear_delay = 30
        self.select_fingerprint = lambda fp: None


def load_doc_commands() -> list[str]:
    text = Path("docs/docs/content/01-getting-started/01-advanced_cli.md").read_text()
    cmds = set(re.findall(r"`seedpass ([^`<>]+)`", text))
    cmds = {c for c in cmds if "<" not in c and ">" not in c}
    cmds.discard("vault export")
    cmds.discard("vault import")
    return sorted(cmds)


runner = CliRunner()


def _setup(monkeypatch):
    monkeypatch.setattr(cli, "PasswordManager", lambda: DummyPM())
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr(cli.api_module, "start_server", lambda fp: "token")
    monkeypatch.setitem(
        sys.modules, "requests", SimpleNamespace(post=lambda *a, **kw: None)
    )
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **kw: "")


import pytest


@pytest.mark.parametrize("command", load_doc_commands())
def test_doc_cli_examples(monkeypatch, command):
    _setup(monkeypatch)
    result = runner.invoke(cli.app, shlex.split(command))
    assert result.exit_code == 0
