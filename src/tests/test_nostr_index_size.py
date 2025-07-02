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
            npub = client.key_manager.get_npub()
            vault = Vault(enc_mgr, tmpdir)
            entry_mgr = EntryManager(vault, Path(tmpdir))

            delay = float(os.getenv("NOSTR_TEST_DELAY", "5"))
            size = 16
            entry_count = 0
            max_payload = 60 * 1024
            try:
                while True:
                    entry_mgr.add_entry(
                        website_name=f"site-{entry_count + 1}",
                        length=12,
                        username="u" * size,
                        url="https://example.com/" + "a" * size,
                    )
                    entry_count += 1
                    encrypted = vault.get_encrypted_index()
                    payload_size = len(encrypted) if encrypted else 0
                    published = client.publish_json_to_nostr(encrypted or b"")
                    time.sleep(delay)
                    retrieved = client.retrieve_json_from_nostr_sync()
                    retrieved_ok = retrieved == encrypted
                    results.append((entry_count, payload_size, published, retrieved_ok))
                    if not published or not retrieved_ok or payload_size > max_payload:
                        break
                    size *= 2
            except Exception:
                results.append((entry_count + 1, None, False, False))
            finally:
                client.close_client_pool()

    note_kind = Kind.from_std(KindStandard.TEXT_NOTE).as_u16()
    print(f"\nNostr note Kind: {note_kind}")
    print(f"Nostr account npub: {npub}")
    print("Count | Payload Bytes | Published | Retrieved")
    for cnt, payload, pub, ret in results:
        print(f"{cnt:>5} | {payload:>13} | {pub} | {ret}")

    synced = sum(1 for _, _, pub, ret in results if pub and ret)
    print(f"Successfully synced entries: {synced}")
