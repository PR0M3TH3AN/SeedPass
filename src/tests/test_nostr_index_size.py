import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import asyncio
import gzip
import sys
import uuid

import pytest

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager
from nostr.client import NostrClient, Kind, KindStandard


@pytest.mark.desktop
@pytest.mark.network
def test_nostr_index_size_limits(pytestconfig: pytest.Config):
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
                f"size_test_{uuid.uuid4().hex}",
                relays=["wss://relay.snort.social"],
            )
            npub = client.key_manager.get_npub()
            vault = Vault(enc_mgr, tmpdir)
            cfg_mgr = ConfigManager(vault, Path(tmpdir))
            backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
            entry_mgr = EntryManager(vault, backup_mgr)

            delay = float(os.getenv("NOSTR_TEST_DELAY", "5"))
            max_entries = pytestconfig.getoption("--max-entries")
            size = 16
            batch = 100
            entry_count = 0
            max_payload = 60 * 1024
            try:
                while max_entries is None or entry_count < max_entries:
                    for _ in range(batch):
                        if max_entries is not None and entry_count >= max_entries:
                            break
                        entry_mgr.add_entry(
                            label=f"site-{entry_count + 1}",
                            length=12,
                            username="u" * size,
                            url="https://example.com/" + "a" * size,
                        )
                        entry_count += 1

                    encrypted = vault.get_encrypted_index()
                    payload_size = len(encrypted) if encrypted else 0
                    asyncio.run(client.publish_snapshot(encrypted or b""))
                    time.sleep(delay)
                    result = asyncio.run(client.fetch_latest_snapshot())
                    retrieved = gzip.decompress(b"".join(result[1])) if result else None
                    retrieved_ok = retrieved == encrypted
                    if not retrieved_ok:
                        print(f"Initial retrieve failed: {client.last_error}")
                        result = asyncio.run(client.fetch_latest_snapshot())
                        retrieved = (
                            gzip.decompress(b"".join(result[1])) if result else None
                        )
                        retrieved_ok = retrieved == encrypted
                    if not retrieved_ok:
                        print("Trying alternate relay")
                        client.update_relays(["wss://relay.damus.io"])
                        result = asyncio.run(client.fetch_latest_snapshot())
                        retrieved = (
                            gzip.decompress(b"".join(result[1])) if result else None
                        )
                        retrieved_ok = retrieved == encrypted
                    results.append((entry_count, payload_size, True, retrieved_ok))
                    if max_entries is not None:
                        if entry_count >= max_entries:
                            break
                    else:
                        if not retrieved_ok or payload_size > max_payload:
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
        payload_str = str(payload) if payload is not None else "N/A"
        print(f"{cnt:>5} | {payload_str:>13} | {pub} | {ret}")

    synced = sum(1 for _, _, pub, ret in results if pub and ret)
    print(f"Successfully synced entries: {synced}")
