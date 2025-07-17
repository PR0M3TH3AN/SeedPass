import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.fingerprint_manager import FingerprintManager
from password_manager.manager import PasswordManager, EncryptionMode
from helpers import create_vault, dummy_nostr_client
import gzip
from nostr.backup_models import Manifest, ChunkMeta


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


def test_sync_index_missing_bad_data(monkeypatch, dummy_nostr_client):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        dir_path = Path(tmpdir)
        vault, _enc = create_vault(dir_path)

        pm = PasswordManager.__new__(PasswordManager)
        pm.fingerprint_dir = dir_path
        pm.vault = vault
        pm.nostr_client = client
        pm.sync_vault = lambda *a, **k: None

        manifest = Manifest(
            ver=1,
            algo="aes-gcm",
            chunks=[ChunkMeta(id="c0", size=1, hash="00")],
            delta_since=None,
        )
        monkeypatch.setattr(
            client,
            "fetch_latest_snapshot",
            lambda: (manifest, [gzip.compress(b"garbage")]),
        )
        monkeypatch.setattr(client, "fetch_deltas_since", lambda *_a, **_k: [])

        result = pm.attempt_initial_sync()
        assert result is False
        index_path = dir_path / "seedpass_entries_db.json.enc"
        assert not index_path.exists()


def test_attempt_initial_sync_incomplete_data(monkeypatch, dummy_nostr_client):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        dir_path = Path(tmpdir)
        vault, _enc = create_vault(dir_path)

        pm = PasswordManager.__new__(PasswordManager)
        pm.fingerprint_dir = dir_path
        pm.vault = vault
        pm.nostr_client = client
        pm.sync_vault = lambda *a, **k: None

        # Simulate relay snapshot retrieval failure due to missing chunks
        monkeypatch.setattr(client, "fetch_latest_snapshot", lambda: None)

        result = pm.attempt_initial_sync()
        assert result is False
        index_path = dir_path / "seedpass_entries_db.json.enc"
        assert not index_path.exists()
