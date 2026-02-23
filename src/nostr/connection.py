import asyncio
import base64
import json
import logging
from datetime import timedelta
from typing import List, Optional

import websockets
from . import client as nostr_client
from constants import MAX_RETRIES, RETRY_DELAY

logger = logging.getLogger("nostr.client")
logger.setLevel(logging.WARNING)

DEFAULT_RELAYS = [
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
]


class ConnectionHandler:
    """Mixin providing relay connection and retry logic."""

    async def connect(self) -> None:
        """Connect the client to all configured relays."""
        if self.offline_mode or not self.relays:
            return
        if not getattr(self, "_connected", False):
            await self._initialize_client_pool()

    def initialize_client_pool(self) -> None:
        """Add relays to the client and connect."""
        if self.offline_mode or not self.relays:
            return
        asyncio.run(self._initialize_client_pool())

    async def _connect_async(self) -> None:
        """Ensure the client is connected within an async context."""
        if self.offline_mode or not self.relays:
            return
        if not getattr(self, "_connected", False):
            await self._initialize_client_pool()

    async def _initialize_client_pool(self) -> None:
        if self.offline_mode or not self.relays:
            return

        formatted = []
        for relay in self.relays:
            if isinstance(relay, str):
                try:
                    formatted.append(nostr_client.RelayUrl.parse(relay))
                except Exception:
                    logger.error("Invalid relay URL: %s", relay)
            else:
                formatted.append(relay)

        if hasattr(self.client, "add_relays"):
            await self.client.add_relays(formatted)
        else:
            for relay in formatted:
                await self.client.add_relay(relay)

        await self.client.connect()
        self._connected = True
        logger.info("NostrClient connected to relays: %s", formatted)

    async def _ping_relay(self, relay: str, timeout: float) -> bool:
        """Attempt to retrieve the latest event from a single relay."""
        sub_id = "seedpass-health"
        pubkey = self.keys.public_key().to_hex()
        req = json.dumps(
            [
                "REQ",
                sub_id,
                {"kinds": [1], "authors": [pubkey], "limit": 1},
            ]
        )
        try:
            async with websockets.connect(
                relay, open_timeout=timeout, close_timeout=timeout
            ) as ws:
                await ws.send(req)
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    data = json.loads(msg)
                    if data[0] in {"EVENT", "EOSE"}:
                        return True
        except Exception:
            return False

    async def _check_relay_health(self, min_relays: int, timeout: float) -> int:
        tasks = [self._ping_relay(r, timeout) for r in self.relays]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        healthy = sum(1 for r in results if r is True)
        if healthy < min_relays:
            logger.warning(
                "Only %s relays responded with data; consider adding more.", healthy
            )
        return healthy

    def check_relay_health(self, min_relays: int = 2, timeout: float = 5.0) -> int:
        """Ping relays and return the count of those providing data."""
        if self.offline_mode or not self.relays:
            return 0
        return asyncio.run(self._check_relay_health(min_relays, timeout))

    async def publish_json_to_nostr(
        self,
        encrypted_json: bytes,
        to_pubkey: str | None = None,
        alt_summary: str | None = None,
    ) -> str | None:
        """Build and publish a Kind 1 text note or direct message."""
        if self.offline_mode or not self.relays:
            return None
        await self.connect()
        self.last_error = None
        try:
            content = base64.b64encode(encrypted_json).decode("utf-8")

            if to_pubkey:
                receiver = nostr_client.PublicKey.parse(to_pubkey)
                event_output = self.client.send_private_msg_to(
                    self.relays, receiver, content
                )
            else:
                builder = nostr_client.EventBuilder.text_note(content)
                if alt_summary:
                    builder = builder.tags([nostr_client.Tag.alt(alt_summary)])
                event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
                event_output = await self.publish_event(event)

            event_id_hex = (
                event_output.id.to_hex()
                if hasattr(event_output, "id")
                else str(event_output)
            )
            logger.info("Successfully published event with ID: %s", event_id_hex)
            return event_id_hex

        except Exception as e:
            self.last_error = str(e)
            logger.error("Failed to publish JSON to Nostr: %s", e)
            return None

    async def publish_event(self, event):
        """Publish a prepared event to the configured relays."""
        if self.offline_mode or not self.relays:
            return None
        await self.connect()
        return await self.client.send_event(event)

    def update_relays(self, new_relays: List[str]) -> None:
        """Reconnect the client using a new set of relays."""
        self.close_client_pool()
        self.relays = new_relays
        signer = nostr_client.NostrSigner.keys(self.keys)
        self.client = nostr_client.Client(signer)
        self._connected = False
        self.initialize_client_pool()

    async def retrieve_json_from_nostr(
        self, retries: int | None = None, delay: float | None = None
    ) -> Optional[bytes]:
        """Retrieve the latest Kind 1 event from the author with optional retries."""
        if self.offline_mode or not self.relays:
            return None

        if retries is None or delay is None:
            if self.config_manager is None:
                from seedpass.core.config_manager import ConfigManager
                from seedpass.core.vault import Vault

                cfg_mgr = ConfigManager(
                    Vault(self.encryption_manager, self.fingerprint_dir),
                    self.fingerprint_dir,
                )
            else:
                cfg_mgr = self.config_manager
            cfg = cfg_mgr.load_config(require_pin=False)
            retries = int(cfg.get("nostr_max_retries", MAX_RETRIES))
            delay = float(cfg.get("nostr_retry_delay", RETRY_DELAY))

        await self.connect()
        self.last_error = None
        for attempt in range(retries):
            try:
                result = await self._retrieve_json_from_nostr()
                if result is not None:
                    return result
            except Exception as e:
                self.last_error = str(e)
                logger.error("Failed to retrieve events from Nostr: %s", e)
            if attempt < retries - 1:
                sleep_time = delay * (2**attempt)
                await asyncio.sleep(sleep_time)
        return None

    async def _retrieve_json_from_nostr(self) -> Optional[bytes]:
        if self.offline_mode or not self.relays:
            return None
        await self._connect_async()
        pubkey = self.keys.public_key()
        f = (
            nostr_client.Filter()
            .author(pubkey)
            .kind(nostr_client.Kind.from_std(nostr_client.KindStandard.TEXT_NOTE))
            .limit(1)
        )
        timeout = timedelta(seconds=10)
        events = (await self.client.fetch_events(f, timeout)).to_vec()
        if not events:
            self.last_error = "No events found on relays for this user."
            logger.warning(self.last_error)
            return None
        latest_event = events[0]
        content_b64 = latest_event.content()
        if content_b64:
            return base64.b64decode(content_b64.encode("utf-8"))
        self.last_error = "Latest event contained no content"
        return None

    def close_client_pool(self) -> None:
        """Disconnect the client from all relays."""
        try:
            asyncio.run(self.client.disconnect())
            self._connected = False
            logger.info("NostrClient disconnected from relays.")
        except Exception as e:
            logger.error("Error during NostrClient shutdown: %s", e)
