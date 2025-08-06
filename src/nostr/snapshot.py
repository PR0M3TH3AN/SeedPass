import asyncio
import base64
import gzip
import hashlib
import json
import logging
import time
from datetime import timedelta
from typing import Tuple

from . import client as nostr_client

from constants import MAX_RETRIES, RETRY_DELAY

from .backup_models import (
    ChunkMeta,
    Manifest,
    KIND_DELTA,
    KIND_MANIFEST,
    KIND_SNAPSHOT_CHUNK,
)

logger = logging.getLogger("nostr.client")
logger.setLevel(logging.WARNING)

# Identifier prefix for replaceable manifest events
MANIFEST_ID_PREFIX = "seedpass-manifest-"


def prepare_snapshot(
    encrypted_bytes: bytes, limit: int
) -> Tuple[Manifest, list[bytes]]:
    """Compress and split the encrypted vault into chunks."""
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


class SnapshotHandler:
    """Mixin providing chunk and manifest handling."""

    async def publish_snapshot(
        self, encrypted_bytes: bytes, limit: int = 50_000
    ) -> tuple[Manifest, str]:
        start = time.perf_counter()
        if self.offline_mode or not self.relays:
            return Manifest(ver=1, algo="gzip", chunks=[]), ""
        await self.ensure_manifest_is_current()
        await self._connect_async()
        manifest, chunks = prepare_snapshot(encrypted_bytes, limit)

        existing: dict[str, str] = {}
        if self.current_manifest:
            for old in self.current_manifest.chunks:
                if old.hash and old.event_id:
                    existing[old.hash] = old.event_id

        for meta, chunk in zip(manifest.chunks, chunks):
            cached_id = existing.get(meta.hash)
            if cached_id:
                meta.event_id = cached_id
                continue
            content = base64.b64encode(chunk).decode("utf-8")
            builder = nostr_client.EventBuilder(
                nostr_client.Kind(KIND_SNAPSHOT_CHUNK), content
            ).tags([nostr_client.Tag.identifier(meta.id)])
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
            nostr_client.EventBuilder(nostr_client.Kind(KIND_MANIFEST), manifest_json)
            .tags([nostr_client.Tag.identifier(manifest_identifier)])
            .build(self.keys.public_key())
            .sign_with_keys(self.keys)
        )
        await self.client.send_event(manifest_event)
        with self._state_lock:
            self.current_manifest = manifest
            self.current_manifest_id = manifest_identifier
            self.current_manifest.delta_since = int(time.time())
            self._delta_events = []
        if getattr(self, "verbose_timing", False):
            duration = time.perf_counter() - start
            logger.info("publish_snapshot completed in %.2f seconds", duration)
        return manifest, manifest_identifier

    async def _fetch_chunks_with_retry(
        self, manifest_event
    ) -> tuple[Manifest, list[bytes]] | None:
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
                cf = (
                    nostr_client.Filter()
                    .author(pubkey)
                    .kind(nostr_client.Kind(KIND_SNAPSHOT_CHUNK))
                )
                if meta.event_id:
                    cf = cf.id(nostr_client.EventId.parse(meta.event_id))
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
        self, keys_obj: nostr_client.Keys
    ) -> tuple[Manifest, list[bytes]] | None:
        """Retrieve the manifest and chunks using ``keys_obj``."""
        self.keys = keys_obj
        pubkey = self.keys.public_key()
        timeout = timedelta(seconds=10)

        ident = f"{MANIFEST_ID_PREFIX}{self.fingerprint}"
        f = (
            nostr_client.Filter()
            .author(pubkey)
            .kind(nostr_client.Kind(KIND_MANIFEST))
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
            ident = MANIFEST_ID_PREFIX.rstrip("-")
            f = (
                nostr_client.Filter()
                .author(pubkey)
                .kind(nostr_client.Kind(KIND_MANIFEST))
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
        return None

    async def fetch_latest_snapshot(self) -> Tuple[Manifest, list[bytes]] | None:
        """Retrieve the latest manifest and all snapshot chunks."""
        if self.offline_mode or not self.relays:
            return None
        await self._connect_async()
        self.last_error = None
        logger.debug("Searching for backup with current keys...")
        try:
            primary_keys = nostr_client.Keys.parse(
                self.key_manager.keys.private_key_hex()
            )
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
            legacy_sdk_keys = nostr_client.Keys.parse(legacy_keys.private_key_hex())
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
        f = (
            nostr_client.Filter()
            .author(pubkey)
            .kind(nostr_client.Kind(KIND_MANIFEST))
            .identifier(ident)
            .limit(1)
        )
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
        if self.offline_mode or not self.relays:
            return ""
        await self.ensure_manifest_is_current()
        await self._connect_async()
        content = base64.b64encode(delta_bytes).decode("utf-8")
        tag = nostr_client.Tag.event(nostr_client.EventId.parse(manifest_id))
        builder = nostr_client.EventBuilder(
            nostr_client.Kind(KIND_DELTA), content
        ).tags([tag])
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
                    nostr_client.EventBuilder(
                        nostr_client.Kind(KIND_MANIFEST), manifest_json
                    )
                    .tags([nostr_client.Tag.identifier(self.current_manifest_id)])
                    .build(self.keys.public_key())
                    .sign_with_keys(self.keys)
                )
            self._delta_events.append(delta_id)
        if manifest_event is not None:
            await self.client.send_event(manifest_event)
        return delta_id

    async def fetch_deltas_since(self, version: int) -> list[bytes]:
        if self.offline_mode or not self.relays:
            return []
        await self._connect_async()
        pubkey = self.keys.public_key()
        f = (
            nostr_client.Filter()
            .author(pubkey)
            .kind(nostr_client.Kind(KIND_DELTA))
            .since(nostr_client.Timestamp.from_secs(version))
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
                joined = b"".join(deltas)
                await self.publish_snapshot(joined)
                exp = nostr_client.Timestamp.from_secs(int(time.time()))
                for ev in events:
                    exp_builder = nostr_client.EventBuilder(
                        nostr_client.Kind(KIND_DELTA), ev.content()
                    ).tags([nostr_client.Tag.expiration(exp)])
                    exp_event = exp_builder.build(
                        self.keys.public_key()
                    ).sign_with_keys(self.keys)
                    await self.client.send_event(exp_event)
        return deltas

    def get_current_manifest(self) -> Manifest | None:
        with self._state_lock:
            return self.current_manifest

    def get_current_manifest_id(self) -> str | None:
        with self._state_lock:
            return self.current_manifest_id

    def get_delta_events(self) -> list[str]:
        with self._state_lock:
            return list(self._delta_events)
