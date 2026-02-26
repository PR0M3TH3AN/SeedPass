import sys
import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))


from utils.fingerprint_manager import FingerprintManager  # noqa: E402
import utils.password_prompt  # noqa: E402
import constants  # noqa: E402
import seedpass.core.manager as manager_module  # noqa: E402
from seedpass.core.entry_management import EntryManager  # noqa: E402
from seedpass.core.backup import BackupManager  # noqa: E402
from seedpass.core.manager import EncryptionMode  # noqa: E402
from seedpass.core.config_manager import ConfigManager  # noqa: E402


def test_add_and_delete_entry(monkeypatch):
    """Test adding and deleting an entry with mocked input and confirmation."""
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        app_dir = tmp_path / ".seedpass"
        parent_seed_file = app_dir / "parent_seed.enc"
        checksum_file = app_dir / "seedpass_script_checksum.txt"

        monkeypatch.setattr(constants, "APP_DIR", app_dir)
        monkeypatch.setattr(constants, "PARENT_SEED_FILE", parent_seed_file)
        monkeypatch.setattr(constants, "SCRIPT_CHECKSUM_FILE", checksum_file)

        monkeypatch.setattr(manager_module, "APP_DIR", app_dir)
        monkeypatch.setattr(manager_module, "PARENT_SEED_FILE", parent_seed_file)
        monkeypatch.setattr(manager_module, "SCRIPT_CHECKSUM_FILE", checksum_file)

        pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        # Initialize fingerprint_manager with the monkeypatched APP_DIR
        # Use manager_module.APP_DIR to ensure consistency within the manager module context
        pm.fingerprint_manager = FingerprintManager(manager_module.APP_DIR)
        pm.current_fingerprint = None
        pm.save_and_encrypt_seed = lambda seed, fingerprint_dir: None
        pm.initialize_bip85 = lambda: None
        pm.initialize_managers = lambda: None
        pm.sync_index_from_nostr_if_missing = lambda: None

        seed = "abandon " * 11 + "about"
        monkeypatch.setattr(
            manager_module.PasswordManager, "generate_bip85_seed", lambda self: seed
        )
        # Mock confirm_action in both locations to be safe against reload issues
        monkeypatch.setattr(manager_module, "confirm_action", lambda *_a, **_k: True)
        monkeypatch.setattr(
            utils.password_prompt, "confirm_action", lambda *_a, **_k: True
        )

        # Robust input mock:
        # 1. "3" -> Select "Generate a new seed"
        # 2. "y" -> Confirm action (fallback if confirm_action mock missed)
        # 3. "y" -> Confirm again (fallback)
        # 4. "y" -> Confirm again (fallback)
        # 5. "y" -> Confirm again (fallback)
        # Using "y" breaks the loop in confirm_action if it gets called.
        input_values = iter(["3", "y", "y", "y", "y"])
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(input_values))

        pm.add_new_fingerprint()

        fingerprint = pm.current_fingerprint
        fingerprint_dir = constants.APP_DIR / fingerprint
        pm.fingerprint_dir = fingerprint_dir

        assert fingerprint_dir.exists()
        assert pm.fingerprint_manager.current_fingerprint == fingerprint

        vault, enc_mgr = create_vault(fingerprint_dir, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fingerprint_dir)
        backup_mgr = BackupManager(fingerprint_dir, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr

        index = entry_mgr.add_entry("example.com", 12)
        assert str(index) in vault.load_index()["entries"]

        published = []
        pm.nostr_client = SimpleNamespace(
            publish_snapshot=lambda data, alt_summary=None: (
                published.append(data),
                (None, "abcd"),
            )[1]
        )

        inputs = iter([str(index)])
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(inputs))
        monkeypatch.setattr(
            pm,
            "start_background_vault_sync",
            lambda *a, **k: pm.sync_vault(*a, **k),
        )

        pm.delete_entry()

        assert str(index) not in vault.load_index()["entries"]
        assert published
