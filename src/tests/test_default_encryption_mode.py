import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from types import SimpleNamespace
from pathlib import Path

from seedpass.core.manager import PasswordManager
from utils.key_derivation import EncryptionMode


def test_default_encryption_mode(monkeypatch):
    monkeypatch.setattr(
        PasswordManager,
        "initialize_fingerprint_manager",
        lambda self: setattr(
            self,
            "fingerprint_manager",
            SimpleNamespace(
                get_current_fingerprint_dir=lambda: Path("./"),
                list_fingerprints=lambda: [],
            ),
        ),
    )
    monkeypatch.setattr(PasswordManager, "setup_parent_seed", lambda self: None)

    pm = PasswordManager()
    assert pm.encryption_mode is EncryptionMode.SEED_ONLY
