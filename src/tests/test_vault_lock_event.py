from seedpass.core.manager import PasswordManager
from seedpass.core.pubsub import bus


def test_lock_vault_publishes_event():
    pm = PasswordManager.__new__(PasswordManager)
    pm.entry_manager = None
    pm.encryption_manager = None
    pm.password_generator = None
    pm.backup_manager = None
    pm.vault = None
    pm.bip85 = None
    pm.nostr_client = None
    pm.config_manager = None
    pm.locked = False
    pm._parent_seed_secret = None

    called = []

    def handler():
        called.append(True)

    bus.subscribe("vault_locked", handler)
    pm.lock_vault()
    bus.unsubscribe("vault_locked", handler)

    assert pm.locked
    assert called == [True]
