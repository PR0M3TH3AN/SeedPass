import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, AsyncMock
import asyncio
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from nostr.client import NostrClient


def test_backup_and_publish_to_nostr():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        # create an index by adding an entry
        entry_mgr.add_entry("example.com", 12)
        encrypted_index = entry_mgr.get_encrypted_index()
        assert encrypted_index is not None

        with patch(
            "nostr.client.NostrClient.publish_snapshot",
            AsyncMock(return_value=(None, "abcd")),
        ) as mock_publish, patch("nostr.client.ClientBuilder"), patch(
            "nostr.client.KeyManager"
        ), patch.object(
            NostrClient, "initialize_client_pool"
        ), patch.object(
            enc_mgr, "decrypt_parent_seed", return_value="seed"
        ):
            nostr_client = NostrClient(enc_mgr, "fp")
            entry_mgr.backup_manager.create_backup()
            result = asyncio.run(nostr_client.publish_snapshot(encrypted_index))

        mock_publish.assert_awaited_with(encrypted_index)
        assert result == (None, "abcd")
