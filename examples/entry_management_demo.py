from pathlib import Path
from cryptography.fernet import Fernet

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from constants import initialize_app


def main() -> None:
    """Demonstrate basic EntryManager usage."""
    initialize_app()
    key = Fernet.generate_key()
    enc = EncryptionManager(key, Path("."))
    vault = Vault(enc, Path("."))
    backup_mgr = BackupManager(Path("."))
    manager = EntryManager(vault, backup_mgr)

    index = manager.add_entry(
        "Example Website",
        16,
        username="user123",
        url="https://example.com",
    )
    print(manager.retrieve_entry(index))
    manager.list_all_entries()


if __name__ == "__main__":
    main()
