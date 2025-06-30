import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from cryptography.fernet import Fernet
from types import SimpleNamespace
import time

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient


def test_nostr_client_uses_custom_relays():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        custom_relays = ["wss://relay1", "wss://relay2"]

        with patch("nostr.client.RelayManager") as MockManager, patch(
            "nostr.client.KeyManager"
        ), patch.object(NostrClient, "initialize_client_pool"):
            with patch.object(enc_mgr, "decrypt_parent_seed", return_value="seed"):
                client = NostrClient(enc_mgr, "fp", relays=custom_relays)

        assert client.relays == custom_relays
        added = [c.args[0] for c in MockManager.return_value.add_relay.call_args_list]
        assert added == custom_relays


def test_wait_for_connection_timeout():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))

        with patch.object(NostrClient, "initialize_client_pool"), patch(
            "nostr.client.RelayManager"
        ), patch("nostr.client.KeyManager"), patch.object(
            enc_mgr, "decrypt_parent_seed", return_value="seed"
        ):
            client = NostrClient(enc_mgr, "fp")

    client.client_pool = SimpleNamespace(connection_statuses={"wss://r": False})

    start = time.monotonic()
    client.wait_for_connection(timeout=0.2)
    duration = time.monotonic() - start
    assert duration >= 0.2
