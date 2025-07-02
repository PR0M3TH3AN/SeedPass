import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager, EncryptionMode


class FakeBackupManager:
    def __init__(self, calls):
        self.calls = calls

    def create_backup(self):
        self.calls["create"] += 1

    def restore_latest_backup(self):
        self.calls["restore"] += 1


def _make_pm():
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    return pm


def test_handle_verify_checksum_success(monkeypatch, tmp_path, capsys):
    pm = _make_pm()
    chk_file = tmp_path / "chk.txt"
    chk_file.write_text("abc")
    monkeypatch.setattr("password_manager.manager.SCRIPT_CHECKSUM_FILE", chk_file)
    monkeypatch.setattr("password_manager.manager.calculate_checksum", lambda _: "abc")
    pm.handle_verify_checksum()
    out = capsys.readouterr().out
    assert "Checksum verification passed." in out


def test_handle_verify_checksum_failure(monkeypatch, tmp_path, capsys):
    pm = _make_pm()
    chk_file = tmp_path / "chk.txt"
    chk_file.write_text("xyz")
    monkeypatch.setattr("password_manager.manager.SCRIPT_CHECKSUM_FILE", chk_file)
    monkeypatch.setattr("password_manager.manager.calculate_checksum", lambda _: "abc")
    pm.handle_verify_checksum()
    out = capsys.readouterr().out
    assert "Checksum verification failed" in out


def test_handle_verify_checksum_missing(monkeypatch, tmp_path, capsys):
    pm = _make_pm()
    chk_file = tmp_path / "chk.txt"
    monkeypatch.setattr("password_manager.manager.SCRIPT_CHECKSUM_FILE", chk_file)
    monkeypatch.setattr("password_manager.manager.calculate_checksum", lambda _: "abc")

    def raise_missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("password_manager.manager.verify_checksum", raise_missing)
    pm.handle_verify_checksum()
    out = capsys.readouterr().out.lower()
    assert "update_checksum.py" in out


def test_backup_and_restore_database(monkeypatch, capsys):
    pm = _make_pm()
    calls = {"create": 0, "restore": 0}
    pm.backup_manager = FakeBackupManager(calls)
    pm.backup_database()
    out1 = capsys.readouterr().out
    pm.restore_database()
    out2 = capsys.readouterr().out
    assert calls["create"] == 1
    assert calls["restore"] == 1
    assert "Backup created successfully." in out1
    assert "Database restored from the latest backup successfully." in out2
