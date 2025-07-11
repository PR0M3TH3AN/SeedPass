# src/nostr/client.py

import base64
import json
import logging
import time
from typing import List, Optional, Tuple
import hashlib
import asyncio
import gzip
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
)
from datetime import timedelta
from nostr_sdk import EventId, Timestamp

from .key_manager import KeyManager as SeedPassKeyManager
from .backup_models import Manifest, ChunkMeta, KIND_MANIFEST, KIND_SNAPSHOT_CHUNK
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
    ) -> None:
        self.encryption_manager = encryption_manager
        self.fingerprint = fingerprint
        self.fingerprint_dir = self.encryption_manager.fingerprint_dir

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

        self.relays = relays if relays else DEFAULT_RELAYS

        # store the last error encountered during network operations
        self.last_error: Optional[str] = None

        self.delta_threshold = 100
        self.current_manifest: Manifest | None = None
        self._delta_events: list[str] = []

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
        return asyncio.run(self._publish_event(event))

    async def _publish_event(self, event):
        return await self.client.send_event(event)

    def update_relays(self, new_relays: List[str]) -> None:
        """Reconnect the client using a new set of relays."""
        self.close_client_pool()
        self.relays = new_relays
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)
        self.initialize_client_pool()

    def retrieve_json_from_nostr_sync(
        self, retries: int = 0, delay: float = 2.0
    ) -> Optional[bytes]:
        """Retrieve the latest Kind 1 event from the author with optional retries."""
        self.last_error = None
        attempt = 0
        while True:
            try:
                result = asyncio.run(self._retrieve_json_from_nostr())
                if result is not None:
                    return result
            except Exception as e:
                self.last_error = str(e)
                logger.error("Failed to retrieve events from Nostr: %s", e)
            if attempt >= retries:
                break
            attempt += 1
            time.sleep(delay)
        return None

    async def _retrieve_json_from_nostr(self) -> Optional[bytes]:
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

        manifest, chunks = prepare_snapshot(encrypted_bytes, limit)
        for meta, chunk in zip(manifest.chunks, chunks):
            content = base64.b64encode(chunk).decode("utf-8")
            builder = EventBuilder(Kind(KIND_SNAPSHOT_CHUNK), content).tags(
                [Tag.identifier(meta.id)]
            )
            event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
            await self.client.send_event(event)

        manifest_json = json.dumps(
            {
                "ver": manifest.ver,
                "algo": manifest.algo,
                "chunks": [meta.__dict__ for meta in manifest.chunks],
                "delta_since": manifest.delta_since,
            }
        )

        manifest_event = (
            EventBuilder(Kind(KIND_MANIFEST), manifest_json)
            .build(self.keys.public_key())
            .sign_with_keys(self.keys)
        )
        result = await self.client.send_event(manifest_event)
        manifest_id = result.id.to_hex() if hasattr(result, "id") else str(result)
        self.current_manifest = manifest
        self._delta_events = []
        return manifest, manifest_id

    async def fetch_latest_snapshot(self) -> Tuple[Manifest, list[bytes]] | None:
        """Retrieve the latest manifest and all snapshot chunks."""

        pubkey = self.keys.public_key()
        f = Filter().author(pubkey).kind(Kind(KIND_MANIFEST)).limit(1)
        timeout = timedelta(seconds=10)
        events = (await self.client.fetch_events(f, timeout)).to_vec()
        if not events:
            return None
        manifest_raw = events[0].content()
        data = json.loads(manifest_raw)
        manifest = Manifest(
            ver=data["ver"],
            algo=data["algo"],
            chunks=[ChunkMeta(**c) for c in data["chunks"]],
            delta_since=data.get("delta_since"),
        )

        chunks: list[bytes] = []
        for meta in manifest.chunks:
            cf = (
                Filter()
                .author(pubkey)
                .kind(Kind(KIND_SNAPSHOT_CHUNK))
                .identifier(meta.id)
                .limit(1)
            )
            cev = (await self.client.fetch_events(cf, timeout)).to_vec()
            if not cev:
                raise ValueError(f"Missing chunk {meta.id}")
            chunk_bytes = base64.b64decode(cev[0].content().encode("utf-8"))
            if hashlib.sha256(chunk_bytes).hexdigest() != meta.hash:
                raise ValueError(f"Checksum mismatch for chunk {meta.id}")
            chunks.append(chunk_bytes)

        self.current_manifest = manifest
        return manifest, chunks

    async def publish_delta(self, delta_bytes: bytes, manifest_id: str) -> str:
        """Publish a delta event referencing a manifest."""

        content = base64.b64encode(delta_bytes).decode("utf-8")
        tag = Tag.event(EventId.parse(manifest_id))
        builder = EventBuilder(Kind(KIND_DELTA), content).tags([tag])
        event = builder.build(self.keys.public_key()).sign_with_keys(self.keys)
        result = await self.client.send_event(event)
        delta_id = result.id.to_hex() if hasattr(result, "id") else str(result)
        if self.current_manifest is not None:
            self.current_manifest.delta_since = delta_id
        self._delta_events.append(delta_id)
        return delta_id

    async def fetch_deltas_since(self, version: int) -> list[bytes]:
        """Retrieve delta events newer than the given version."""

        pubkey = self.keys.public_key()
        f = (
            Filter()
            .author(pubkey)
            .kind(Kind(KIND_DELTA))
            .since(Timestamp.from_secs(version))
        )
        timeout = timedelta(seconds=10)
        events = (await self.client.fetch_events(f, timeout)).to_vec()
        deltas: list[bytes] = []
        for ev in events:
            deltas.append(base64.b64decode(ev.content().encode("utf-8")))

        if self.current_manifest is not None:
            snap_size = sum(c.size for c in self.current_manifest.chunks)
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

    def close_client_pool(self) -> None:
        """Disconnects the client from all relays."""
        try:
            asyncio.run(self.client.disconnect())
            logger.info("NostrClient disconnected from relays.")
        except Exception as e:
            logger.error("Error during NostrClient shutdown: %s", e)
