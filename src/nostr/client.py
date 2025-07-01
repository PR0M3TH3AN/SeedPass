import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Callable, List, Optional

from pynostr.websocket_relay_manager import WebSocketRelayManager
from pynostr.event import Event, EventKind
from pynostr.encrypted_dm import EncryptedDirectMessage

from .key_manager import KeyManager
from password_manager.encryption import EncryptionManager
from .event_handler import EventHandler
from utils.file_lock import exclusive_lock

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

DEFAULT_RELAYS = [
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
]


class NostrClient:
    """Interact with the Nostr network using pynostr."""

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint: str,
        relays: Optional[List[str]] = None,
    ) -> None:
        self.encryption_manager = encryption_manager
        self.fingerprint = fingerprint
        self.fingerprint_dir = self.encryption_manager.fingerprint_dir
        self.key_manager = KeyManager(
            self.encryption_manager.decrypt_parent_seed(), fingerprint
        )
        self.event_handler = EventHandler()
        self.relays = relays if relays else DEFAULT_RELAYS
        self.client_pool = None
        self.subscriptions: set[str] = set()
        self.initialize_client_pool()

    def initialize_client_pool(self) -> None:
        """Create the relay manager and connect to configured relays."""
        self.client_pool = WebSocketRelayManager()
        for relay in self.relays:
            self.client_pool.add_relay(relay)

    async def publish_event_async(self, event: Event) -> None:
        logger.debug("Publishing event %s", event.id)
        self.client_pool.publish_event(event)

    def publish_event(self, event: Event) -> None:
        self.client_pool.publish_event(event)

    async def subscribe_async(
        self,
        filters: List[dict],
        handler: Callable[[WebSocketRelayManager, str, Event], None],
        timeout: float = 2.0,
    ) -> None:
        sub_id = str(uuid.uuid4())
        from pynostr.filters import FiltersList

        filter_list = FiltersList.from_json_array(filters)
        self.client_pool.add_subscription_on_all_relays(sub_id, filter_list)
        self.subscriptions.add(sub_id)

        end = asyncio.get_event_loop().time() + timeout
        try:
            while asyncio.get_event_loop().time() < end:
                while self.client_pool.message_pool.has_events():
                    msg = self.client_pool.message_pool.get_event()
                    if msg.subscription_id == sub_id:
                        handler(self.client_pool, sub_id, msg.event)
                await asyncio.sleep(0.1)
        finally:
            self.client_pool.close_subscription_on_all_relays(sub_id)
            self.subscriptions.discard(sub_id)

    def subscribe(
        self,
        filters: List[dict],
        handler: Callable[[WebSocketRelayManager, str, Event], None],
        timeout: float = 2.0,
    ) -> None:
        asyncio.run(self.subscribe_async(filters, handler, timeout))

    async def retrieve_json_from_nostr_async(self) -> Optional[str]:
        filters = [
            {
                "authors": [self.key_manager.keys.public_key_hex()],
                "kinds": [EventKind.TEXT_NOTE, EventKind.ENCRYPTED_DIRECT_MESSAGE],
                "limit": 1,
            }
        ]
        events: list[Event] = []

        async def handler(_client, _sid, evt: Event):
            events.append(evt)

        await self.subscribe_async(filters, handler)

        if not events:
            return None

        event = events[0]
        content_base64 = event.content
        if event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
            dm = EncryptedDirectMessage.from_event(event)
            dm.decrypt(
                self.key_manager.keys.private_key_hex(), public_key_hex=dm.pubkey
            )
            content_base64 = dm.cleartext_content
        return content_base64

    def retrieve_json_from_nostr(self) -> Optional[str]:
        return asyncio.run(self.retrieve_json_from_nostr_async())

    async def do_post_async(self, text: str) -> None:
        event = Event(kind=EventKind.TEXT_NOTE, content=text)
        event.pubkey = self.key_manager.keys.public_key_hex()
        event.created_at = int(time.time())
        event.sign(self.key_manager.keys.private_key_hex())
        await self.publish_event_async(event)

    async def subscribe_feed_async(
        self, handler: Callable[[WebSocketRelayManager, str, Event], None]
    ) -> None:
        filters = [
            {
                "authors": [self.key_manager.keys.public_key_hex()],
                "kinds": [EventKind.TEXT_NOTE, EventKind.ENCRYPTED_DIRECT_MESSAGE],
                "limit": 100,
            }
        ]
        await self.subscribe_async(filters, handler)

    async def publish_and_subscribe_async(self, text: str) -> None:
        await asyncio.gather(
            self.do_post_async(text),
            self.subscribe_feed_async(self.event_handler.handle_new_event),
        )

    def publish_and_subscribe(self, text: str) -> None:
        asyncio.run(self.publish_and_subscribe_async(text))

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
        data = json.loads(decrypted_data.decode("utf-8"))
        self.save_json_data(data)
        self.update_checksum()

    def save_json_data(self, data: dict) -> None:
        encrypted_data = self.encryption_manager.encrypt_data(
            json.dumps(data).encode("utf-8")
        )
        index_file_path = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
        with exclusive_lock(index_file_path):
            with open(index_file_path, "wb") as f:
                f.write(encrypted_data)

    def update_checksum(self) -> None:
        index_file_path = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
        decrypted_data = self.decrypt_data_from_file(index_file_path)
        content = decrypted_data.decode("utf-8")
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()
        checksum_file = self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
        with exclusive_lock(checksum_file):
            with open(checksum_file, "w") as f:
                f.write(checksum)
        checksum_file.chmod(0o600)

    def decrypt_data_from_file(self, file_path: Path) -> bytes:
        with exclusive_lock(file_path):
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
        return self.encryption_manager.decrypt_data(encrypted_data)

    def publish_json_to_nostr(
        self, encrypted_json: bytes, to_pubkey: str | None = None
    ) -> bool:
        try:
            content = base64.b64encode(encrypted_json).decode("utf-8")
            if to_pubkey:
                dm = EncryptedDirectMessage()
                dm.encrypt(
                    private_key_hex=self.key_manager.keys.private_key_hex(),
                    cleartext_content=content,
                    recipient_pubkey=to_pubkey,
                )
                event = dm.to_event()
            else:
                event = Event(kind=EventKind.TEXT_NOTE, content=content)
                event.pubkey = self.key_manager.keys.public_key_hex()
            event.created_at = int(time.time())
            event.sign(self.key_manager.keys.private_key_hex())
            self.publish_event(event)
            return True
        except Exception as e:  # pragma: no cover - defensive
            logger.error("Failed to publish JSON to Nostr: %s", e)
            return False

    def retrieve_json_from_nostr_sync(self) -> Optional[bytes]:
        content = self.retrieve_json_from_nostr()
        if content:
            return base64.urlsafe_b64decode(content.encode("utf-8"))
        return None

    def decrypt_and_save_index_from_nostr_public(self, encrypted_data: bytes) -> None:
        self.decrypt_and_save_index_from_nostr(encrypted_data)

    async def close_client_pool_async(self) -> None:
        self.client_pool.close_all_relay_connections()

    def close_client_pool(self) -> None:
        self.client_pool.close_all_relay_connections()

    async def safe_close_connection(self, client):  # pragma: no cover - compatibility
        try:
            await client.close_connection()
        except Exception:
            pass
