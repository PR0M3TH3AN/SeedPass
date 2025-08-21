import asyncio
import base64
import json
import logging
import time
import threading
from datetime import timedelta
from typing import List, Optional, TYPE_CHECKING

import websockets
from nostr_sdk import (
    Client,
    EventBuilder,
    Filter,
    Kind,
    KindStandard,
    NostrSigner,
    Tag,
    RelayUrl,
    PublicKey,
)
from nostr_sdk import EventId, Keys, Timestamp

from constants import MAX_RETRIES, RETRY_DELAY
from seedpass.core.encryption import EncryptionManager

from .backup_models import (
    ChunkMeta,
    KIND_DELTA,
    KIND_MANIFEST,
    KIND_SNAPSHOT_CHUNK,
    Manifest,
)
from .connection import ConnectionHandler, DEFAULT_RELAYS
from .key_manager import KeyManager as SeedPassKeyManager
from .snapshot import SnapshotHandler, prepare_snapshot

if TYPE_CHECKING:  # pragma: no cover - imported for type hints
    from seedpass.core.config_manager import ConfigManager

# Backwards compatibility for tests that patch these symbols
KeyManager = SeedPassKeyManager
ClientBuilder = Client

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class NostrClient(ConnectionHandler, SnapshotHandler):
    """Interact with the Nostr network using nostr-sdk."""

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint: str,
        relays: Optional[List[str]] = None,
        parent_seed: Optional[str] = None,
        offline_mode: bool = False,
        config_manager: Optional["ConfigManager"] = None,
        key_index: bytes | None = None,
        account_index: int | None = None,
    ) -> None:
        self.encryption_manager = encryption_manager
        self.fingerprint = fingerprint
        self.fingerprint_dir = self.encryption_manager.fingerprint_dir
        self.config_manager = config_manager
        self.verbose_timing = False

        if parent_seed is None:
            parent_seed = self.encryption_manager.decrypt_parent_seed()

        # Use our project's KeyManager to derive the private key
        self.key_manager = KeyManager(parent_seed, fingerprint, account_index)

        # Create a nostr-sdk Keys object from our derived private key
        private_key_hex = self.key_manager.keys.private_key_hex()
        if not isinstance(private_key_hex, str):
            private_key_hex = "0" * 64
        try:
            self.keys = Keys.parse(private_key_hex)
        except Exception:
            self.keys = Keys.generate()

        self.offline_mode = offline_mode
        if relays is None:
            self.relays = [] if offline_mode else DEFAULT_RELAYS
        else:
            self.relays = relays

        if self.config_manager is not None:
            try:
                self.verbose_timing = self.config_manager.get_verbose_timing()
            except Exception:
                self.verbose_timing = False

        # store the last error encountered during network operations
        self.last_error: Optional[str] = None

        self.delta_threshold = 100
        self._state_lock = threading.Lock()
        self.current_manifest: Manifest | None = None
        self.current_manifest_id: str | None = None
        self._delta_events: list[str] = []
        self.key_index = key_index or b""

        # Configure and initialize the nostr-sdk Client
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)

        self._connected = False


__all__ = [
    "NostrClient",
    "prepare_snapshot",
    "DEFAULT_RELAYS",
]
