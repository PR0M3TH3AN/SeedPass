import os
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import asyncio
import gzip
import uuid

import pytest
import base64

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
        enc_mgr = EncryptionManager(
            base64.urlsafe_b64encode(os.urandom(32)), Path(tmpdir)
        )
        with patch.object(enc_mgr, "decrypt_parent_seed", return_value=seed):
            client = NostrClient(
                enc_mgr,
                f"test_fp_{uuid.uuid4().hex}",
                relays=["wss://relay.snort.social"],
            )
            payload = b"seedpass"
            asyncio.run(client.publish_snapshot(payload))
            time.sleep(2)
            result = asyncio.run(client.fetch_latest_snapshot())
            retrieved = gzip.decompress(b"".join(result[1])) if result else None
            client.close_client_pool()
            assert retrieved == payload
