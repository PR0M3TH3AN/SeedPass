import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def _setup(tmp_path: Path) -> PasswordManager:
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
    pm.nostr_client = FakeNostrClient()
    pm.fingerprint_dir = tmp_path
    pm.is_dirty = False
    pm.secret_mode_enabled = False
    pm.password_generator = SimpleNamespace(bip85=object())
    return pm


def test_retrieve_ssh(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = _setup(tmp_path)
        idx = pm.entry_manager.add_ssh_key()
        monkeypatch.setattr(
            "password_manager.manager.derive_ssh_key",
            lambda b, i: bytes.fromhex("11" * 32),
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: str(idx))
        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert "SSH key" in out
        assert "11" * 32 in out


def test_retrieve_seed(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = _setup(tmp_path)
        idx = pm.entry_manager.add_seed()
        monkeypatch.setattr(
            "password_manager.manager.derive_seed_phrase",
            lambda b, i, w: "word " * w,
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: str(idx))
        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert "Seed Phrase" in out or "seed" in out.lower()
        assert "word" in out
