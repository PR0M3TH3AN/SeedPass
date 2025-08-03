# src/nostr/client.py

import base64
import json
import logging
import time
from typing import List, Optional, Tuple, TYPE_CHECKING
import hashlib
import asyncio
import gzip
import threading
import websockets

# Imports from the nostr-sdk library
from nostr_sdk import (
    Client,
    Keys,
    NostrSigner,
    EventBuilder,
    Filter,
    Kind,
    KindStandard,
    Tag,
    RelayUrl,
)
from datetime import timedelta
from nostr_sdk import EventId, Timestamp

from .key_manager import KeyManager as SeedPassKeyManager
from .backup_models import Manifest, ChunkMeta, KIND_MANIFEST, KIND_SNAPSHOT_CHUNK
from seedpass.core.encryption import EncryptionManager
from constants import MAX_RETRIES, RETRY_DELAY
from utils.file_lock import exclusive_lock

if TYPE_CHECKING:  # pragma: no cover - imported for type hints
    from seedpass.core.config_manager import ConfigManager

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

# Identifier prefix for replaceable manifest events
MANIFEST_ID_PREFIX = "seedpass-manifest-"


def prepare_snapshot(
    encrypted_bytes: bytes, limit: int
) -> Tuple[Manifest, list[bytes]]:
    """Compress and split the encrypted vault into chunks.

    Each chunk is hashed with SHA-256 and described in the returned
    :class:`Manifest`.

    Parameters
    ----------
    encrypted_bytes : bytes
        The encrypted vault contents.
    limit : int
        Maximum chunk size in bytes.

    Returns
    -------
    Tuple[Manifest, list[bytes]]
        The manifest describing all chunks and the list of chunk bytes.
    """

    compressed = gzip.compress(encrypted_bytes)
    chunks = [compressed[i : i + limit] for i in range(0, len(compressed), limit)]

    metas: list[ChunkMeta] = []
    for i, chunk in enumerate(chunks):
        metas.append(
            ChunkMeta(
                id=f"seedpass-chunk-{i:04d}",
                size=len(chunk),
                hash=hashlib.sha256(chunk).hexdigest(),
                event_id=None,
            )
        )

    manifest = Manifest(ver=1, algo="gzip", chunks=metas)
    return manifest, chunks


class NostrClient:
    """Interact with the Nostr network using nostr-sdk."""

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint: str,
        relays: Optional[List[str]] = None,
        parent_seed: Optional[str] = None,
        offline_mode: bool = False,
        config_manager: Optional["ConfigManager"] = None,
    ) -> None:
        self.encryption_manager = encryption_manager
        self.fingerprint = fingerprint
        self.fingerprint_dir = self.encryption_manager.fingerprint_dir
        self.config_manager = config_manager
        self.verbose_timing = False

        if parent_seed is None:
            parent_seed = self.encryption_manager.decrypt_parent_seed()

        # Use our project's KeyManager to derive the private key
        self.key_manager = KeyManager(parent_seed, fingerprint)

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

        # Configure and initialize the nostr-sdk Client
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)

        self._connected = False

    def connect(self) -> None:
        """Connect the client to all configured relays."""
        if self.offline_mode or not self.relays:
            return
        if not self._connected:
            self.initialize_client_pool()

    def initialize_client_pool(self) -> None:
        """Add relays to the client and connect."""
        if self.offline_mode or not self.relays:
            return
        asyncio.run(self._initialize_client_pool())

    async def _connect_async(self) -> None:
        """Ensure the client is connected within an async context."""
        if self.offline_mode or not self.relays:
            return
        if not self._connected:
            await self._initialize_client_pool()

    async def _initialize_client_pool(self) -> None:
        if self.offline_mode or not self.relays:
            return

        formatted = []
        for relay in self.relays:
            if isinstance(relay, str):
                try:
                    formatted.append(RelayUrl.parse(relay))
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
            ["REQ", sub_id, {"kinds": [1], "authors": [pubkey], "limit": 1}]
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

    def publish_json_to_nostr(
        self,
        encrypted_json: bytes,
        to_pubkey: str | None = None,
        alt_summary: str | None = None,
    ) -> str | None:
        """Builds and publishes a Kind 1 text note or direct message.

        Parameters
        ----------
        encrypted_json : bytes
            The encrypted index data to publish.
        to_pubkey : str | None, optional
            If provided, send as a direct message to this public key.
        alt_summary : str | None, optional
            If provided, include an ``alt`` tag so uploads can be
            associated with a specific event like a password change.
        """
        if self.offline_mode or not self.relays:
            return None
        self.connect()
        self.last_error = None
        try:
            content = base64.b64encode(encrypted_json).decode("utf-8")

            if to_pubkey:
                receiver = PublicKey.parse(to_pubkey)
                event_output = self.client.send_private_msg_to(
                    self.relays, receiver, content
                )
            else:
                builder = EventBuilder.text_note(content)
                if alt_summary:
                    builder = builder.tags([Tag.alt(alt_summary)])
                event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
                event_output = self.publish_event(event)

            event_id_hex = (
                event_output.id.to_hex()
                if hasattr(event_output, "id")
                else str(event_output)
            )
            logger.info(f"Successfully published event with ID: {event_id_hex}")
            return event_id_hex

        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Failed to publish JSON to Nostr: {e}")
            return None

    def publish_event(self, event):
        """Publish a prepared event to the configured relays."""
        if self.offline_mode or not self.relays:
            return None
        self.connect()
        return asyncio.run(self._publish_event(event))

    async def _publish_event(self, event):
        if self.offline_mode or not self.relays:
            return None
        await self._connect_async()
        return await self.client.send_event(event)

    def update_relays(self, new_relays: List[str]) -> None:
        """Reconnect the client using a new set of relays."""
        self.close_client_pool()
        self.relays = new_relays
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)
        self._connected = False
        # Immediately reconnect using the updated relay list
        self.initialize_client_pool()

    def retrieve_json_from_nostr_sync(
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

        self.connect()
        self.last_error = None
        for attempt in range(retries):
            try:
                result = asyncio.run(self._retrieve_json_from_nostr())
                if result is not None:
                    return result
            except Exception as e:
                self.last_error = str(e)
                logger.error("Failed to retrieve events from Nostr: %s", e)
            if attempt < retries - 1:
                sleep_time = delay * (2**attempt)
                time.sleep(sleep_time)
        return None

    async def _retrieve_json_from_nostr(self) -> Optional[bytes]:
        if self.offline_mode or not self.relays:
            return None
        await self._connect_async()
        # Filter for the latest text note (Kind 1) from our public key
        pubkey = self.keys.public_key()
        f = Filter().author(pubkey).kind(Kind.from_std(KindStandard.TEXT_NOTE)).limit(1)

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

    async def publish_snapshot(
        self, encrypted_bytes: bytes, limit: int = 50_000
    ) -> tuple[Manifest, str]:
        """Publish a compressed snapshot split into chunks.

        Parameters
        ----------
        encrypted_bytes : bytes
            Vault contents already encrypted with the user's key.
        limit : int, optional
            Maximum chunk size in bytes. Defaults to 50 kB.
        """

        start = time.perf_counter()
        if self.offline_mode or not self.relays:
            return Manifest(ver=1, algo="gzip", chunks=[]), ""
        await self.ensure_manifest_is_current()
        await self._connect_async()
        manifest, chunks = prepare_snapshot(encrypted_bytes, limit)
        for meta, chunk in zip(manifest.chunks, chunks):
            content = base64.b64encode(chunk).decode("utf-8")
            builder = EventBuilder(Kind(KIND_SNAPSHOT_CHUNK), content).tags(
                [Tag.identifier(meta.id)]
            )
            event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
            result = await self.client.send_event(event)
            try:
                meta.event_id = (
                    result.id.to_hex() if hasattr(result, "id") else str(result)
                )
            except Exception:
                meta.event_id = None

        manifest_json = json.dumps(
            {
                "ver": manifest.ver,
                "algo": manifest.algo,
                "chunks": [meta.__dict__ for meta in manifest.chunks],
                "delta_since": manifest.delta_since,
            }
        )

        manifest_identifier = (
            self.current_manifest_id or f"{MANIFEST_ID_PREFIX}{self.fingerprint}"
        )
        manifest_event = (
            EventBuilder(Kind(KIND_MANIFEST), manifest_json)
            .tags([Tag.identifier(manifest_identifier)])
            .build(self.keys.public_key())
            .sign_with_keys(self.keys)
        )
        await self.client.send_event(manifest_event)
        with self._state_lock:
            self.current_manifest = manifest
            self.current_manifest_id = manifest_identifier
            # Record when this snapshot was published for future delta events
            self.current_manifest.delta_since = int(time.time())
            self._delta_events = []
        if getattr(self, "verbose_timing", False):
            duration = time.perf_counter() - start
            logger.info("publish_snapshot completed in %.2f seconds", duration)
        return manifest, manifest_identifier

    async def _fetch_chunks_with_retry(
        self, manifest_event
    ) -> tuple[Manifest, list[bytes]] | None:
        """Retrieve all chunks referenced by ``manifest_event`` with retries."""

        pubkey = self.keys.public_key()
        timeout = timedelta(seconds=10)

        try:
            data = json.loads(manifest_event.content())
            manifest = Manifest(
                ver=data["ver"],
                algo=data["algo"],
                chunks=[ChunkMeta(**c) for c in data["chunks"]],
                delta_since=(
                    int(data["delta_since"])
                    if data.get("delta_since") is not None
                    else None
                ),
            )
        except Exception:
            return None

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
        max_retries = int(cfg.get("nostr_max_retries", MAX_RETRIES))
        delay = float(cfg.get("nostr_retry_delay", RETRY_DELAY))

        chunks: list[bytes] = []
        for meta in manifest.chunks:
            chunk_bytes: bytes | None = None
            for attempt in range(max_retries):
                cf = Filter().author(pubkey).kind(Kind(KIND_SNAPSHOT_CHUNK))
                if meta.event_id:
                    cf = cf.id(EventId.parse(meta.event_id))
                else:
                    cf = cf.identifier(meta.id)
                cf = cf.limit(1)
                cev = (await self.client.fetch_events(cf, timeout)).to_vec()
                if cev:
                    candidate = base64.b64decode(cev[0].content().encode("utf-8"))
                    if hashlib.sha256(candidate).hexdigest() == meta.hash:
                        chunk_bytes = candidate
                        break
                if attempt < max_retries - 1:
                    await asyncio.sleep(delay * (2**attempt))
            if chunk_bytes is None:
                return None
            chunks.append(chunk_bytes)

        ident = None
        try:
            tags_obj = manifest_event.tags()
            ident = tags_obj.identifier()
        except Exception:
            tags = getattr(manifest_event, "tags", None)
            if callable(tags):
                tags = tags()
            if tags:
                tag = tags[0]
                if hasattr(tag, "as_vec"):
                    vec = tag.as_vec()
                    if vec and len(vec) >= 2:
                        ident = vec[1]
                elif isinstance(tag, (list, tuple)) and len(tag) >= 2:
                    ident = tag[1]
                elif isinstance(tag, str):
                    ident = tag
        with self._state_lock:
            self.current_manifest = manifest
            self.current_manifest_id = ident
        return manifest, chunks

    async def _fetch_manifest_with_keys(
        self, keys_obj: Keys
    ) -> tuple[Manifest, list[bytes]] | None:
        """Attempt to retrieve the manifest and chunks using ``keys_obj``.

        ``self.keys`` is updated to ``keys_obj`` so that subsequent chunk and
        delta downloads use the same public key that succeeded.
        """

        self.keys = keys_obj
        pubkey = self.keys.public_key()
        timeout = timedelta(seconds=10)

        ident = f"{MANIFEST_ID_PREFIX}{self.fingerprint}"
        f = Filter().author(pubkey).kind(Kind(KIND_MANIFEST)).identifier(ident).limit(1)
        try:
            events = (await self.client.fetch_events(f, timeout)).to_vec()
        except Exception as e:  # pragma: no cover - network errors
            self.last_error = str(e)
            logger.error(
                "Failed to fetch manifest from relays %s: %s",
                self.relays,
                e,
            )
            return None

        if not events:
            ident = MANIFEST_ID_PREFIX.rstrip("-")
            f = (
                Filter()
                .author(pubkey)
                .kind(Kind(KIND_MANIFEST))
                .identifier(ident)
                .limit(1)
            )
            try:
                events = (await self.client.fetch_events(f, timeout)).to_vec()
            except Exception as e:  # pragma: no cover - network errors
                self.last_error = str(e)
                logger.error(
                    "Failed to fetch manifest from relays %s: %s",
                    self.relays,
                    e,
                )
                return None
            if not events:
                return None

        logger.info("Fetched manifest using identifier %s", ident)

        for manifest_event in events:
            try:
                result = await self._fetch_chunks_with_retry(manifest_event)
                if result is not None:
                    return result
            except Exception as e:  # pragma: no cover - network errors
                self.last_error = str(e)
                logger.error(
                    "Error retrieving snapshot from relays %s: %s",
                    self.relays,
                    e,
                )
        # manifest was found but chunks missing
        return None

    async def fetch_latest_snapshot(self) -> Tuple[Manifest, list[bytes]] | None:
        """Retrieve the latest manifest and all snapshot chunks."""
        if self.offline_mode or not self.relays:
            return None
        await self._connect_async()

        self.last_error = None

        logger.debug("Searching for backup with current keys...")
        try:
            primary_keys = Keys.parse(self.key_manager.keys.private_key_hex())
        except Exception:
            primary_keys = self.keys

        result = await self._fetch_manifest_with_keys(primary_keys)
        if result is not None:
            return result

        logger.warning(
            "No backup found with current keys. Falling back to legacy key derivation..."
        )
        try:
            legacy_keys = self.key_manager.generate_legacy_nostr_keys()
            legacy_sdk_keys = Keys.parse(legacy_keys.private_key_hex())
        except Exception as e:
            self.last_error = str(e)
            return None

        result = await self._fetch_manifest_with_keys(legacy_sdk_keys)
        if result is not None:
            logger.info("Found legacy backup with old key derivation.")
            return result

        if self.last_error is None:
            self.last_error = "No backup found on Nostr relays."

        return None

    async def ensure_manifest_is_current(self) -> None:
        """Verify the local manifest is up to date before publishing."""
        if self.offline_mode or not self.relays:
            return
        await self._connect_async()
        pubkey = self.keys.public_key()
        ident = self.current_manifest_id or f"{MANIFEST_ID_PREFIX}{self.fingerprint}"
        f = Filter().author(pubkey).kind(Kind(KIND_MANIFEST)).identifier(ident).limit(1)
        timeout = timedelta(seconds=10)
        try:
            events = (await self.client.fetch_events(f, timeout)).to_vec()
        except Exception:
            return
        if not events:
            return
        try:
            data = json.loads(events[0].content())
            remote = data.get("delta_since")
            if remote is not None:
                remote = int(remote)
        except Exception:
            return
        with self._state_lock:
            local = self.current_manifest.delta_since if self.current_manifest else None
        if remote is not None and (local is None or remote > local):
            self.last_error = "Manifest out of date"
            raise RuntimeError("Manifest out of date")

    async def publish_delta(self, delta_bytes: bytes, manifest_id: str) -> str:
        """Publish a delta event referencing a manifest."""
        if self.offline_mode or not self.relays:
            return ""
        await self.ensure_manifest_is_current()
        await self._connect_async()

        content = base64.b64encode(delta_bytes).decode("utf-8")
        tag = Tag.event(EventId.parse(manifest_id))
        builder = EventBuilder(Kind(KIND_DELTA), content).tags([tag])
        event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
        result = await self.client.send_event(event)
        delta_id = result.id.to_hex() if hasattr(result, "id") else str(result)
        created_at = getattr(
            event, "created_at", getattr(event, "timestamp", int(time.time()))
        )
        if hasattr(created_at, "secs"):
            created_at = created_at.secs
        manifest_event = None
        with self._state_lock:
            if self.current_manifest is not None:
                self.current_manifest.delta_since = int(created_at)
                manifest_json = json.dumps(
                    {
                        "ver": self.current_manifest.ver,
                        "algo": self.current_manifest.algo,
                        "chunks": [
                            meta.__dict__ for meta in self.current_manifest.chunks
                        ],
                        "delta_since": self.current_manifest.delta_since,
                    }
                )
                manifest_event = (
                    EventBuilder(Kind(KIND_MANIFEST), manifest_json)
                    .tags([Tag.identifier(self.current_manifest_id)])
                    .build(self.keys.public_key())
                    .sign_with_keys(self.keys)
                )
            self._delta_events.append(delta_id)
        if manifest_event is not None:
            await self.client.send_event(manifest_event)
        return delta_id

    async def fetch_deltas_since(self, version: int) -> list[bytes]:
        """Retrieve delta events newer than the given version."""
        if self.offline_mode or not self.relays:
            return []
        await self._connect_async()

        pubkey = self.keys.public_key()
        f = (
            Filter()
            .author(pubkey)
            .kind(Kind(KIND_DELTA))
            .since(Timestamp.from_secs(version))
        )
        timeout = timedelta(seconds=10)
        events = (await self.client.fetch_events(f, timeout)).to_vec()
        events.sort(
            key=lambda ev: getattr(ev, "created_at", getattr(ev, "timestamp", 0))
        )
        deltas: list[bytes] = []
        for ev in events:
            deltas.append(base64.b64decode(ev.content().encode("utf-8")))

        manifest = self.get_current_manifest()
        if manifest is not None:
            snap_size = sum(c.size for c in manifest.chunks)
            if (
                len(deltas) >= self.delta_threshold
                or sum(len(d) for d in deltas) > snap_size
            ):
                # Publish a new snapshot to consolidate deltas
                joined = b"".join(deltas)
                await self.publish_snapshot(joined)
                exp = Timestamp.from_secs(int(time.time()))
                for ev in events:
                    exp_builder = EventBuilder(Kind(KIND_DELTA), ev.content()).tags(
                        [Tag.expiration(exp)]
                    )
                    exp_event = exp_builder.build(
                        self.keys.public_key()
                    ).sign_with_keys(self.keys)
                    await self.client.send_event(exp_event)
        return deltas

    def get_current_manifest(self) -> Manifest | None:
        """Thread-safe access to ``current_manifest``."""
        with self._state_lock:
            return self.current_manifest

    def get_current_manifest_id(self) -> str | None:
        """Thread-safe access to ``current_manifest_id``."""
        with self._state_lock:
            return self.current_manifest_id

    def get_delta_events(self) -> list[str]:
        """Thread-safe snapshot of pending delta event IDs."""
        with self._state_lock:
            return list(self._delta_events)

    def close_client_pool(self) -> None:
        """Disconnects the client from all relays."""
        try:
            asyncio.run(self.client.disconnect())
            self._connected = False
            logger.info("NostrClient disconnected from relays.")
        except Exception as e:
            logger.error("Error during NostrClient shutdown: %s", e)
