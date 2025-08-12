import pytest
from types import SimpleNamespace

from seedpass.core.manager import PasswordManager
from seedpass.errors import VaultLockedError


class DummyEntryManager:
    def __init__(self):
        self.cleared = False

    def clear_cache(self):
        self.cleared = True


def test_lock_vault_sets_flag_and_keeps_objects():
    pm = PasswordManager.__new__(PasswordManager)
    em = DummyEntryManager()
    pm.entry_manager = em
    pm.is_locked = False
    pm.locked = False
    pm.lock_vault()
    assert pm.is_locked
    assert pm.locked
    assert pm.entry_manager is em
    assert em.cleared


def test_entry_service_requires_unlocked():
    pm = PasswordManager.__new__(PasswordManager)
    service = SimpleNamespace()
    pm._entry_service = service
    pm.is_locked = True
    with pytest.raises(VaultLockedError):
        _ = pm.entry_service
    pm.is_locked = False
    assert pm.entry_service is service


def test_unlock_vault_clears_locked_flag(tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.parent_seed = "seed"
    pm.setup_encryption_manager = lambda *a, **k: None
    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    pm.update_activity = lambda: None
    pm.is_locked = True
    pm.locked = True
    pm.unlock_vault("pw")
    assert not pm.is_locked
    assert not pm.locked
