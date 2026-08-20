import sys
import importlib
import queue
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from nostr.client import DEFAULT_RELAYS
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import Notification, PasswordManager
from seedpass.core.state_manager import StateManager
from seedpass.core.vault import Vault
from seedpass.core.errors import SeedPassError
from utils.fingerprint_manager import FingerprintManager
from utils.password_prompt import PasswordPromptError


def setup_pm(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    import constants

    importlib.reload(constants)
    importlib.reload(main)

    fp_dir = constants.APP_DIR / "fp"
    fp_dir.mkdir(parents=True)
    vault, enc_mgr = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, fp_dir)
    fp_mgr = FingerprintManager(constants.APP_DIR)

    nostr_stub = SimpleNamespace(
        relays=list(DEFAULT_RELAYS),
        close_client_pool=lambda: None,
        initialize_client_pool=lambda: None,
        publish_snapshot=lambda data, alt_summary=None: (None, "abcd"),
        key_manager=SimpleNamespace(get_npub=lambda: "npub"),
    )

    pm = SimpleNamespace(
        config_manager=cfg_mgr,
        fingerprint_manager=fp_mgr,
        nostr_client=nostr_stub,
    )
    return pm, cfg_mgr, fp_mgr


def test_relay_and_profile_actions(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, cfg_mgr, fp_mgr = setup_pm(tmp_path, monkeypatch)

        # Add two fingerprints for listing
        fp1 = fp_mgr.add_fingerprint(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        fp2 = fp_mgr.add_fingerprint(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        )

        # Add a relay
        with patch("builtins.input", return_value="wss://new"), patch(
            "main.handle_post_to_nostr"
        ), patch("main._reload_relays"):
            main.handle_add_relay(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert "wss://new" in cfg["relays"]

        # Remove the relay
        idx = cfg["relays"].index("wss://new") + 1
        with patch("builtins.input", return_value=str(idx)), patch(
            "main._reload_relays"
        ):
            main.handle_remove_relay(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert "wss://new" not in cfg["relays"]

        # Reset to defaults
        with patch("main._reload_relays"):
            main.handle_reset_relays(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == list(DEFAULT_RELAYS)

        # List profiles
        main.handle_list_fingerprints(pm)
        out = capsys.readouterr().out
        assert fp1 in out
        assert fp2 in out


def test_settings_menu_additional_backup(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, cfg_mgr, fp_mgr = setup_pm(tmp_path, monkeypatch)

        inputs = iter(["10", ""])
        with patch("main.handle_set_additional_backup_location") as handler:
            with patch("builtins.input", side_effect=lambda *_: next(inputs)):
                main.handle_settings(pm)
        handler.assert_called_once_with(pm)


def test_settings_menu_change_password(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        calls: list[tuple[str, str]] = []
        pm.change_password = lambda old, new: calls.append((old, new))

        inputs = iter(["3", ""])
        monkeypatch.setattr(main, "prompt_existing_password", lambda *_: "oldpw")
        monkeypatch.setattr(main, "prompt_new_password", lambda *_: "newpw")
        monkeypatch.setattr(main, "pause", lambda: None)

        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        assert calls == [("oldpw", "newpw")]


def test_settings_menu_change_password_incorrect(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)

        def fail_change(old, new):
            raise ValueError("Incorrect password")

        pm.change_password = fail_change
        inputs = iter(["3", ""])
        monkeypatch.setattr(main, "prompt_existing_password", lambda *_: "badpw")
        monkeypatch.setattr(main, "prompt_new_password", lambda *_: "newpw")
        monkeypatch.setattr(main, "pause", lambda: None)

        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        out = capsys.readouterr().out
        assert "Incorrect password" in out


def test_settings_menu_without_nostr_client(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    pm.nostr_client = None
    pm.notifications = queue.Queue()
    pm.error_queue = queue.Queue()
    pm.notify = lambda msg, level="INFO": pm.notifications.put(Notification(msg, level))
    pm.is_dirty = False
    pm.last_update = time.time()
    pm.last_activity = time.time()
    pm.update_activity = lambda: None
    pm.lock_vault = lambda: None
    pm.unlock_vault = lambda: None
    pm.start_background_relay_check = lambda: None
    pm.poll_background_errors = PasswordManager.poll_background_errors.__get__(pm)
    pm.display_stats = lambda: None

    inputs = iter(["7", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    monkeypatch.setattr("builtins.input", lambda *_: "")

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)

    assert pm.error_queue.empty()
    assert pm.notifications.empty()


def test_settings_menu_missing_handler_is_graceful(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        # Option 4 calls this method directly in settings.
        if hasattr(pm, "handle_verify_checksum"):
            delattr(pm, "handle_verify_checksum")

        inputs = iter(["4", ""])
        monkeypatch.setattr(main, "pause", lambda: None)
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        out = capsys.readouterr().out
        assert "Unexpected settings error:" in out


def test_settings_lock_unlock_cancelled_is_graceful(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        pm.lock_vault = lambda: None

        def unlock_fail():
            raise PasswordPromptError("Operation cancelled by user")

        pm.unlock_vault = unlock_fail
        pm.start_background_sync = lambda: None
        pm.start_background_relay_check = lambda: None

        inputs = iter(["13", ""])
        monkeypatch.setattr(main, "pause", lambda: None)
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        out = capsys.readouterr().out
        assert "Unlock cancelled: Operation cancelled by user" in out


def test_profiles_submenu_action_error_is_graceful(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, fp_mgr = setup_pm(tmp_path, monkeypatch)
        pm.update_activity = lambda: None
        pm.handle_switch_fingerprint = lambda: (_ for _ in ()).throw(
            SeedPassError("switch failure")
        )

        inputs = iter(["1", ""])
        monkeypatch.setattr(main, "pause", lambda: None)
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_profiles_menu(pm)

        out = capsys.readouterr().out
        assert "Action failed: switch failure" in out


def test_settings_export_failure_message(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        pm.handle_export_database = lambda: (_ for _ in ()).throw(
            RuntimeError("export boom")
        )

        inputs = iter(["7", ""])
        monkeypatch.setattr(main, "pause", lambda: None)
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        out = capsys.readouterr().out
        assert "Export failed: export boom" in out


def test_settings_import_missing_path_message(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        pm.handle_import_database = lambda _path: (_ for _ in ()).throw(
            FileNotFoundError
        )

        inputs = iter(["8", "missing.json.enc", ""])
        monkeypatch.setattr(main, "pause", lambda: None)
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_settings(pm)

        out = capsys.readouterr().out
        assert "Import failed: file 'missing.json.enc' not found." in out


def test_reset_nostr_sync_state(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        fp_dir = tmp_path / ".seedpass" / "fp"
        state_mgr = StateManager(fp_dir)
        state_mgr.update_state(
            manifest_id="manifest-old",
            delta_since=123,
            last_sync_ts=456,
            nostr_account_idx=2,
        )
        pm.state_manager = state_mgr
        pm.fingerprint_dir = fp_dir
        pm.current_fingerprint = "fp"
        pm.manifest_id = "manifest-old"
        pm.delta_since = 123
        pm.last_sync_ts = 456

        monkeypatch.setattr(main, "confirm_action", lambda *_: True)
        monkeypatch.setattr(main, "pause", lambda: None)
        main.handle_reset_nostr_sync_state(pm)

        state = state_mgr.state
        assert state["manifest_id"] is None
        assert state["delta_since"] == 0
        assert state["last_sync_ts"] == 0
        assert state["nostr_account_idx"] == 2
        assert pm.manifest_id is None
        assert pm.delta_since == 0
        assert pm.last_sync_ts == 0
        assert pm.nostr_account_idx == 2


def test_start_fresh_nostr_namespace(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        fp_dir = tmp_path / ".seedpass" / "fp"
        state_mgr = StateManager(fp_dir)
        state_mgr.update_state(
            manifest_id="manifest-old",
            delta_since=123,
            last_sync_ts=456,
            nostr_account_idx=2,
        )
        pm.state_manager = state_mgr
        pm.fingerprint_dir = fp_dir
        pm.current_fingerprint = "fp"
        pm.manifest_id = "manifest-old"
        pm.delta_since = 123
        pm.last_sync_ts = 456
        called = {"reinit": 0}
        pm._initialize_nostr_client = lambda: called.__setitem__(
            "reinit", called["reinit"] + 1
        )

        monkeypatch.setattr(main, "confirm_action", lambda *_: True)
        monkeypatch.setattr(main, "pause", lambda: None)
        main.handle_start_fresh_nostr_namespace(pm)

        state = state_mgr.state
        assert state["manifest_id"] is None
        assert state["delta_since"] == 0
        assert state["last_sync_ts"] == 0
        assert state["nostr_account_idx"] == 3
        assert pm.nostr_account_idx == 3
        assert called["reinit"] == 1


def test_nostr_menu_dispatches_reset_sync_state(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        pm.update_activity = lambda: None
        inputs = iter(["8", ""])
        with patch("main.handle_reset_nostr_sync_state") as handler:
            with patch("builtins.input", side_effect=lambda *_: next(inputs)):
                main.handle_nostr_menu(pm)
        handler.assert_called_once_with(pm)


def test_nostr_menu_dispatches_fresh_namespace(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        pm.update_activity = lambda: None
        inputs = iter(["9", ""])
        with patch("main.handle_start_fresh_nostr_namespace") as handler:
            with patch("builtins.input", side_effect=lambda *_: next(inputs)):
                main.handle_nostr_menu(pm)
        handler.assert_called_once_with(pm)


def test_settings_menu_dispatches_semantic_submenu(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        inputs = iter(["18", ""])
        with patch("main.handle_semantic_index_menu") as handler:
            with patch("builtins.input", side_effect=lambda *_: next(inputs)):
                main.handle_settings(pm)
        handler.assert_called_once_with(pm)


def test_semantic_submenu_search_flow(monkeypatch, capsys):
    class DummySemanticService:
        def __init__(self, _pm):
            self.last_query = None
            self.mode = "keyword"

        def status(self):
            return {"enabled": False, "built": False, "records": 0, "mode": self.mode}

        def set_enabled(self, enabled: bool):
            return {"enabled": bool(enabled), "records": 0}

        def build(self):
            return {"enabled": True, "built": True, "records": 2}

        def rebuild(self):
            return {"enabled": True, "built": True, "records": 2}

        def set_mode(self, mode: str):
            self.mode = str(mode)
            return {"mode": self.mode}

        def search(self, query: str, *, k: int = 10, kind: str | None = None):
            self.last_query = query
            return [{"entry_id": 1, "kind": "document", "label": "Doc", "score": 0.5}]

    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, _, _ = setup_pm(tmp_path, monkeypatch)
        monkeypatch.setattr(main, "SemanticIndexService", DummySemanticService)
        monkeypatch.setattr(main, "pause", lambda: None)
        inputs = iter(["1", "7", "hybrid", "2", "4", "6", "relay docs", ""])
        with patch("builtins.input", side_effect=lambda *_: next(inputs)):
            main.handle_semantic_index_menu(pm)
        out = capsys.readouterr().out
        assert "Status: enabled=False, built=False, records=0, mode=keyword" in out
        assert "Semantic search mode set to hybrid." in out
        assert "Semantic index enabled" in out
        assert "Semantic index built with 2 records" in out
        assert "Semantic Matches:" in out
        assert "#1 [document] Doc" in out
