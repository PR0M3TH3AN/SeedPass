import asyncio
import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Callable, List, Optional

from nostr_sdk import nostr_sdk as sdk
from nostr_sdk import uniffi_set_event_loop

# expose key SDK classes for easier mocking in tests
ClientBuilder = sdk.ClientBuilder
EventBuilder = sdk.EventBuilder
Kind = sdk.Kind
KindStandard = sdk.KindStandard
Filter = sdk.Filter
Keys = sdk.Keys
PublicKey = sdk.PublicKey
Duration = sdk.Duration

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
        self.key_manager = KeyManager(
            self.encryption_manager.decrypt_parent_seed(), fingerprint
        )
        self.event_handler = EventHandler()
        self.relays = relays if relays else DEFAULT_RELAYS
        self.client_pool = None
        self.subscriptions: set[str] = set()
        self.initialize_client_pool()

    def initialize_client_pool(self) -> None:
        """Create the client and connect to configured relays."""

        async def _init() -> None:
            uniffi_set_event_loop(asyncio.get_running_loop())
            self.client_pool = ClientBuilder().build()
            for relay in self.relays:
                await self.client_pool.add_relay(relay)
            await self.client_pool.connect()

        asyncio.run(_init())

    async def publish_event_async(self, event) -> None:
        logger.debug("Publishing event %s", event.id())
        uniffi_set_event_loop(asyncio.get_running_loop())
        await self.client_pool.send_event(event)

    def publish_event(self, event) -> None:
        asyncio.run(self.publish_event_async(event))

    async def subscribe_async(
        self,
        filters: List[dict],
        handler: Callable[[object, str, object], None],
        timeout: float = 2.0,
    ) -> None:
        uniffi_set_event_loop(asyncio.get_running_loop())
        for f in filters:
            flt = Filter()
            if "authors" in f:
                flt = flt.authors([PublicKey.parse(a) for a in f["authors"]])
            if "kinds" in f:
                kinds = []
                for k in f["kinds"]:
                    if k == 1:
                        kinds.append(sdk.Kind.from_std(sdk.KindStandard.TEXT_NOTE))
                    elif k == 4:
                        kinds.append(
                            sdk.Kind.from_std(sdk.KindStandard.PRIVATE_DIRECT_MESSAGE)
                        )
                if kinds:
                    flt = flt.kinds(kinds)
            if "limit" in f:
                flt = flt.limit(f["limit"])

            events = await self.client_pool.fetch_events(flt, Duration(seconds=timeout))
            for evt in events.to_vec():
                handler(self.client_pool, "0", evt)

    def subscribe(
        self,
        filters: List[dict],
        handler: Callable[[object, str, object], None],
        timeout: float = 2.0,
    ) -> None:
        asyncio.run(self.subscribe_async(filters, handler, timeout))

    async def retrieve_json_from_nostr_async(self) -> Optional[str]:
        filters = [
            {
                "authors": [self.key_manager.keys.public_key_hex()],
                "kinds": [1, 4],
                "limit": 1,
            }
        ]
        events: list = []

        async def handler(_client, _sid, evt):
            events.append(evt)

        await self.subscribe_async(filters, handler)

        if not events:
            return None

        event = events[0]
        content_base64 = event.content()
        return content_base64

    def retrieve_json_from_nostr(self) -> Optional[str]:
        return asyncio.run(self.retrieve_json_from_nostr_async())

    async def do_post_async(self, text: str) -> None:
        keys = Keys.parse(self.key_manager.keys.private_key_hex())
        event = (
            EventBuilder.text_note(text).build(keys.public_key()).sign_with_keys(keys)
        )
        await self.publish_event_async(event)

    async def subscribe_feed_async(
        self, handler: Callable[[object, str, object], None]
    ) -> None:
        filters = [
            {
                "authors": [self.key_manager.keys.public_key_hex()],
                "kinds": [1, 4],
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
            keys = Keys.parse(self.key_manager.keys.private_key_hex())
            event = (
                EventBuilder.text_note(content)
                .build(keys.public_key())
                .sign_with_keys(keys)
            )
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
        uniffi_set_event_loop(asyncio.get_running_loop())
        await self.client_pool.disconnect()

    def close_client_pool(self) -> None:
        asyncio.run(self.close_client_pool_async())

    async def safe_close_connection(self, client):  # pragma: no cover - compatibility
        try:
            await client.disconnect()
        except Exception:
            pass
