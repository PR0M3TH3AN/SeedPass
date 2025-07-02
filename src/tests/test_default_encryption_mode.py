import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager
from utils.key_derivation import DEFAULT_ENCRYPTION_MODE


def test_default_encryption_mode():
    assert PasswordManager.__init__.__defaults__[0] is DEFAULT_ENCRYPTION_MODE
