import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.vault import Vault

VALID_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_save_and_encrypt_seed_initializes_vault(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.vault = None
        pm.config_manager = None
        pm.current_fingerprint = "fp"

        monkeypatch.setattr("seedpass.core.manager.prompt_for_password", lambda: "pw")
        monkeypatch.setattr(
            "seedpass.core.manager.NostrClient", lambda *a, **kw: object()
        )

        pm.save_and_encrypt_seed(VALID_SEED, tmp_path)

        assert isinstance(pm.vault, Vault)
        assert pm.entry_manager is not None
