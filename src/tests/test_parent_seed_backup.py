import builtins
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager, EncryptionMode
from constants import DEFAULT_SEED_BACKUP_FILENAME


def _make_pm(tmp_path: Path) -> PasswordManager:
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.parent_seed = "seed phrase"
    pm.fingerprint_dir = tmp_path
    pm.encryption_manager = SimpleNamespace(encrypt_and_save_file=lambda *a, **k: None)
    pm.verify_password = lambda pw: True
    return pm


def test_handle_backup_reveal_parent_seed_confirm(monkeypatch, tmp_path, capsys):
    pm = _make_pm(tmp_path)

    monkeypatch.setattr(
        "password_manager.manager.prompt_existing_password", lambda *_: "pw"
    )
    confirms = iter([True, True])
    monkeypatch.setattr(
        "password_manager.manager.confirm_action", lambda *_a, **_k: next(confirms)
    )
    saved = []

    def fake_save(data, path):
        saved.append((data, path))

    pm.encryption_manager = SimpleNamespace(encrypt_and_save_file=fake_save)
    monkeypatch.setattr(builtins, "input", lambda *_: "mybackup.enc")

    pm.handle_backup_reveal_parent_seed()
    out = capsys.readouterr().out

    assert "seed phrase" in out
    assert saved
    assert saved[0][1] == tmp_path / "mybackup.enc"


def test_handle_backup_reveal_parent_seed_cancel(monkeypatch, tmp_path, capsys):
    pm = _make_pm(tmp_path)

    monkeypatch.setattr(
        "password_manager.manager.prompt_existing_password", lambda *_: "pw"
    )
    monkeypatch.setattr(
        "password_manager.manager.confirm_action", lambda *_a, **_k: False
    )
    saved = []
    pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: saved.append((data, path))
    )

    pm.handle_backup_reveal_parent_seed()
    out = capsys.readouterr().out

    assert "seed phrase" not in out
    assert not saved


def test_is_valid_filename(tmp_path):
    pm = _make_pm(tmp_path)
    invalid = ["../bad", "", "bad/name", "bad\\name", "..", "/absolute"]
    for name in invalid:
        assert not pm.is_valid_filename(name)
    assert pm.is_valid_filename("good.enc")
