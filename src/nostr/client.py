# src/nostr/client.py

import base64
import json
import logging
from typing import List, Optional
import hashlib
import asyncio

# Imports from the nostr-sdk library
from nostr_sdk import (
    Client,
    Keys,
    NostrSigner,
    EventBuilder,
    Filter,
    Kind,
    KindStandard,
)
from datetime import timedelta

from .key_manager import KeyManager as SeedPassKeyManager
from password_manager.encryption import EncryptionManager
from utils.file_lock import exclusive_lock

# Backwards compatibility for tests that patch these symbols
KeyManager = SeedPassKeyManager
ClientBuilder = Client

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

DEFAULT_RELAYS = [
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
]


class NostrClient:
    """Interact with the Nostr network using nostr-sdk."""

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint: str,
        relays: Optional[List[str]] = None,
    ) -> None:
        self.encryption_manager = encryption_manager
        self.fingerprint = fingerprint
        self.fingerprint_dir = self.encryption_manager.fingerprint_dir

        # Use our project's KeyManager to derive the private key
        self.key_manager = KeyManager(
            self.encryption_manager.decrypt_parent_seed(), fingerprint
        )

        # Create a nostr-sdk Keys object from our derived private key
        private_key_hex = self.key_manager.keys.private_key_hex()
        if not isinstance(private_key_hex, str):
            private_key_hex = "0" * 64
        try:
            self.keys = Keys.parse(private_key_hex)
        except Exception:
            self.keys = Keys.generate()

        self.relays = relays if relays else DEFAULT_RELAYS

        # Configure and initialize the nostr-sdk Client
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)

        self.initialize_client_pool()

    def initialize_client_pool(self) -> None:
        """Add relays to the client and connect."""
        asyncio.run(self._initialize_client_pool())

    async def _initialize_client_pool(self) -> None:
        if hasattr(self.client, "add_relays"):
            await self.client.add_relays(self.relays)
        else:
            for relay in self.relays:
                await self.client.add_relay(relay)
        await self.client.connect()
        logger.info(f"NostrClient connected to relays: {self.relays}")

    def publish_json_to_nostr(
        self, encrypted_json: bytes, to_pubkey: str | None = None
    ) -> bool:
        """Builds and publishes a Kind 1 text note to the configured relays."""
        try:
            content = base64.b64encode(encrypted_json).decode("utf-8")

            # Use the EventBuilder to create and sign the event
            event = (
                EventBuilder.text_note(content)
                .build(self.keys.public_key())
                .sign_with_keys(self.keys)
            )

            # Send the event using the client
            event_output = self.publish_event(event)
            event_id_hex = (
                event_output.id.to_hex()
                if hasattr(event_output, "id")
                else str(event_output)
            )
            logger.info(f"Successfully published event with ID: {event_id_hex}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish JSON to Nostr: {e}")
            return False

    def publish_event(self, event):
        """Publish a prepared event to the configured relays."""
        return asyncio.run(self._publish_event(event))

    async def _publish_event(self, event):
        return await self.client.send_event(event)

    def retrieve_json_from_nostr_sync(self) -> Optional[bytes]:
        """Retrieves the latest Kind 1 event from the author."""
        try:
            return asyncio.run(self._retrieve_json_from_nostr())
        except Exception as e:
            logger.error("Failed to retrieve events from Nostr: %s", e)
            return None

    async def _retrieve_json_from_nostr(self) -> Optional[bytes]:
        # Filter for the latest text note (Kind 1) from our public key
        pubkey = self.keys.public_key()
        f = Filter().author(pubkey).kind(Kind.from_std(KindStandard.TEXT_NOTE)).limit(1)

        timeout = timedelta(seconds=10)
        events = (await self.client.fetch_events(f, timeout)).to_vec()

        if not events:
            logger.warning("No events found on relays for this user.")
            return None

        latest_event = events[0]
        content_b64 = latest_event.content()

        if content_b64:
            return base64.b64decode(content_b64.encode("utf-8"))
        return None

    def close_client_pool(self) -> None:
        """Disconnects the client from all relays."""
        try:
            asyncio.run(self.client.disconnect())
            logger.info("NostrClient disconnected from relays.")
        except Exception as e:
            logger.error("Error during NostrClient shutdown: %s", e)
