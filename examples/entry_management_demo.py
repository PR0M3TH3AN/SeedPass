from pathlib import Path
from cryptography.fernet import Fernet

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.entry_management import EntryManager


def main() -> None:
    """Demonstrate basic EntryManager usage."""
    key = Fernet.generate_key()
    enc = EncryptionManager(key, Path("."))
    vault = Vault(enc, Path("."))
    manager = EntryManager(vault, Path("."))

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
