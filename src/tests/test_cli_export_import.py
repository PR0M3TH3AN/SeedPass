from pathlib import Path
from types import SimpleNamespace

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from seedpass.core.portable_backup import export_backup, import_backup
from seedpass.core.config_manager import ConfigManager
from seedpass.core.backup import BackupManager
from helpers import create_vault, TEST_SEED


def _setup_pm(tmp_path: Path):
    vault, _ = create_vault(tmp_path, TEST_SEED)
    cfg = ConfigManager(vault, tmp_path)
    backup = BackupManager(tmp_path, cfg)
    pm = SimpleNamespace(
        handle_export_database=lambda p, encrypt=True: export_backup(
            vault, backup, p, parent_seed=TEST_SEED, encrypt=encrypt
        ),
        handle_import_database=lambda p: import_backup(
            vault, backup, p, parent_seed=TEST_SEED
        ),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
    )
    return pm, vault


def test_cli_export_creates_file(monkeypatch, tmp_path):
    pm, vault = _setup_pm(tmp_path)
    data = {
        "schema_version": 4,
        "entries": {
            "0": {
                "label": "example",
                "type": "password",
                "notes": "",
                "custom_fields": [],
                "origin": "",
                "tags": [],
            }
        },
    }
    vault.save_index(data)

    monkeypatch.setattr(main, "PasswordManager", lambda *a, **k: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)

    export_path = tmp_path / "out.json"
    rc = main.main(["export", "--file", str(export_path)])
    assert rc == 0
    assert export_path.exists()


def test_cli_import_round_trip(monkeypatch, tmp_path):
    pm, vault = _setup_pm(tmp_path)
    original = {
        "schema_version": 4,
        "entries": {
            "0": {
                "label": "example",
                "type": "password",
                "notes": "",
                "custom_fields": [],
                "origin": "",
                "tags": [],
            }
        },
    }
    vault.save_index(original)

    export_path = tmp_path / "out.json"
    export_backup(
        vault,
        BackupManager(tmp_path, ConfigManager(vault, tmp_path)),
        export_path,
        parent_seed=TEST_SEED,
    )

    vault.save_index({"schema_version": 4, "entries": {}})

    monkeypatch.setattr(main, "PasswordManager", lambda *a, **k: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)

    rc = main.main(["import", "--file", str(export_path)])
    assert rc == 0
    assert vault.load_index() == original


def test_cli_export_import_unencrypted(monkeypatch, tmp_path):
    pm, vault = _setup_pm(tmp_path)
    data = {
        "schema_version": 4,
        "entries": {
            "0": {
                "label": "example",
                "type": "password",
                "notes": "",
                "custom_fields": [],
                "origin": "",
                "tags": [],
            }
        },
    }
    vault.save_index(data)

    monkeypatch.setattr(main, "PasswordManager", lambda *a, **k: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)

    export_path = tmp_path / "out.json"
    rc = main.main(["export", "--file", str(export_path), "--unencrypted"])
    assert rc == 0
    assert export_path.exists()

    vault.save_index({"schema_version": 4, "entries": {}})
    rc = main.main(["import", "--file", str(export_path)])
    assert rc == 0
    assert vault.load_index() == data
