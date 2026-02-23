import main
from pathlib import Path


def test_cli_flag_restores_before_init(monkeypatch, tmp_path):
    calls = []
    backup = tmp_path / "bak.json"
    backup.write_text("{}")

    def fake_restore(path, fingerprint):
        calls.append(("restore", Path(path), fingerprint))

    class DummyPM:
        def __init__(self, fingerprint=None):
            calls.append(("init", fingerprint))
            self.secret_mode_enabled = True
            self.inactivity_timeout = 0

    monkeypatch.setattr(main, "restore_backup_index", fake_restore)
    monkeypatch.setattr(main, "PasswordManager", DummyPM)
    monkeypatch.setattr(main, "display_menu", lambda pm, **k: None)

    rc = main.main(["--fingerprint", "fp", "--restore-backup", str(backup)])
    assert rc == 0
    assert calls[0][0] == "restore"
    assert calls[1][0] == "init"
    assert calls[0][1] == backup
    assert calls[0][2] == "fp"


def test_menu_option_restores_before_init(monkeypatch, tmp_path):
    calls = []
    backup = tmp_path / "bak.json"
    backup.write_text("{}")

    def fake_restore(path, fingerprint):
        calls.append(("restore", Path(path), fingerprint))

    class DummyPM:
        def __init__(self, fingerprint=None):
            calls.append(("init", fingerprint))
            self.secret_mode_enabled = True
            self.inactivity_timeout = 0

    monkeypatch.setattr(main, "restore_backup_index", fake_restore)
    monkeypatch.setattr(main, "PasswordManager", DummyPM)
    monkeypatch.setattr(main, "display_menu", lambda pm, **k: None)
    inputs = iter(["2", str(backup)])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))

    rc = main.main(["--fingerprint", "fp"])
    assert rc == 0
    assert calls[0][0] == "restore"
    assert calls[1][0] == "init"
    assert calls[0][1] == backup
    assert calls[0][2] == "fp"
