import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sys

import pytest

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.vault import Vault
from nostr.client import NostrClient, Kind, KindStandard


@pytest.mark.desktop
@pytest.mark.network
@pytest.mark.skipif(not os.getenv("NOSTR_E2E"), reason="NOSTR_E2E not set")
def test_nostr_index_size_limits():
    """Manually explore maximum index size for Nostr backups."""
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon about"
    )
    results = []
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        with patch.object(enc_mgr, "decrypt_parent_seed", return_value=seed):
            client = NostrClient(
                enc_mgr,
                "size_test_fp",
                relays=["wss://relay.snort.social"],
            )
            vault = Vault(enc_mgr, tmpdir)
            entry_mgr = EntryManager(vault, Path(tmpdir))

            sizes = [16, 64, 256, 1024, 2048, 4096, 8192]
            delay = float(os.getenv("NOSTR_TEST_DELAY", "5"))
            for size in sizes:
                try:
                    entry_mgr.add_entry(
                        website_name=f"site-{size}",
                        length=12,
                        username="u" * size,
                        url="https://example.com/" + "a" * size,
                    )
                    encrypted = vault.get_encrypted_index()
                    payload_size = len(encrypted) if encrypted else 0
                    published = client.publish_json_to_nostr(encrypted or b"")
                    time.sleep(delay)
                    retrieved = client.retrieve_json_from_nostr_sync()
                    retrieved_ok = retrieved == encrypted
                    results.append((size, payload_size, published, retrieved_ok))
                    if not published or not retrieved_ok:
                        break
                except Exception:
                    results.append((size, None, False, False))
                    break
            client.close_client_pool()

    note_kind = Kind.from_std(KindStandard.TEXT_NOTE).as_u16()
    print(f"\nNostr note Kind: {note_kind}")
    print("Size | Payload Bytes | Published | Retrieved")
    for size, payload, pub, ret in results:
        print(f"{size:>4} | {payload:>13} | {pub} | {ret}")
