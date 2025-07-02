import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, AsyncMock
import asyncio
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.vault import Vault
from nostr.client import NostrClient


def test_backup_and_publish_to_nostr():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        entry_mgr = EntryManager(vault, tmp_path)

        # create an index by adding an entry
        entry_mgr.add_entry("example.com", 12)
        encrypted_index = entry_mgr.get_encrypted_index()
        assert encrypted_index is not None

        with patch(
            "nostr.client.NostrClient.publish_snapshot",
            AsyncMock(return_value=None),
        ) as mock_publish, patch("nostr.client.ClientBuilder"), patch(
            "nostr.client.KeyManager"
        ), patch.object(
            NostrClient, "initialize_client_pool"
        ), patch.object(
            enc_mgr, "decrypt_parent_seed", return_value="seed"
        ):
            nostr_client = NostrClient(enc_mgr, "fp")
            entry_mgr.backup_index_file()
            result = asyncio.run(nostr_client.publish_snapshot(encrypted_index))

        mock_publish.assert_awaited_with(encrypted_index)
        assert result is None
