import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.fingerprint_manager import FingerprintManager
from password_manager.manager import PasswordManager, EncryptionMode


VALID_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_add_and_switch_fingerprint(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        fm = FingerprintManager(app_dir)

        fingerprint = fm.add_fingerprint(VALID_SEED)
        assert fingerprint in fm.list_fingerprints()
        expected_dir = app_dir / fingerprint
        assert expected_dir.exists()

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.fingerprint_manager = fm
        pm.encryption_manager = object()
        pm.current_fingerprint = None

        monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "1")
        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password",
            lambda *_a, **_k: "pass",
        )
        monkeypatch.setattr(
            PasswordManager,
            "setup_encryption_manager",
            lambda self, d, password=None, exit_on_fail=True: True,
        )
        monkeypatch.setattr(PasswordManager, "load_parent_seed", lambda self, d: None)
        monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
        monkeypatch.setattr(PasswordManager, "initialize_managers", lambda self: None)
        monkeypatch.setattr(
            PasswordManager, "sync_index_from_nostr_if_missing", lambda self: None
        )
        monkeypatch.setattr(
            "password_manager.manager.NostrClient", lambda *a, **kw: object()
        )

        assert pm.handle_switch_fingerprint()
        assert pm.current_fingerprint == fingerprint
        assert fm.current_fingerprint == fingerprint
        assert pm.fingerprint_dir == expected_dir
