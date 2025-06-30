from password_manager.manager import PasswordManager
from nostr.client import NostrClient


def main() -> None:
    """Show how to initialise PasswordManager with Nostr support."""
    manager = PasswordManager()
    manager.nostr_client = NostrClient(encryption_manager=manager.encryption_manager)
    # Sample actions could be called on ``manager`` here.


if __name__ == "__main__":
    main()
