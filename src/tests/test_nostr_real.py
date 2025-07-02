import os
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import uuid

import pytest
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from nostr.client import NostrClient


@pytest.mark.network
@pytest.mark.skipif(not os.getenv("NOSTR_E2E"), reason="NOSTR_E2E not set")
def test_nostr_publish_and_retrieve():
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon about"
    )
    with TemporaryDirectory() as tmpdir:
        enc_mgr = EncryptionManager(Fernet.generate_key(), Path(tmpdir))
        with patch.object(enc_mgr, "decrypt_parent_seed", return_value=seed):
            client = NostrClient(
                enc_mgr,
                f"test_fp_{uuid.uuid4().hex}",
                relays=["wss://relay.snort.social"],
            )
            payload = b"seedpass"
            assert client.publish_json_to_nostr(payload) is True
            time.sleep(2)
            retrieved = client.retrieve_json_from_nostr_sync()
            client.close_client_pool()
            assert retrieved == payload
