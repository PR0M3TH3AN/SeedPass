import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import threading
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

#: How many manifests to fetch before choosing the newest.
#:
#: This used to be 1, which delegated "which snapshot is latest" to the relay:
#: whatever it chose to return was restored. Fetching a handful and ordering
#: them locally by signed publication time takes that decision back. Small
#: because manifests are tiny and only the newest few can ever win.
MANIFEST_FETCH_LIMIT = 16

#: Guards :func:`_next_published_ms` so concurrent publishes cannot collide.
_published_ms_lock = threading.Lock()
_last_published_ms = 0


def _next_published_ms() -> int:
    """Strictly increasing publication timestamp in milliseconds.

    A wall-clock millisecond is not enough on its own: two snapshots published
    back to back can land in the same millisecond, and the ordering then falls
    through to the event-id tie-break -- arbitrary with respect to time, which
    is the bug ``published_ms`` exists to fix, just in a narrower window.
    Forcing each value above the last one this process produced makes it a
    monotonic sequence that also happens to be a timestamp.

    Across processes or machines the clock is still the only shared reference,
    so this narrows the tie window rather than closing it everywhere.

    Must match the TypeScript ``nextPublishedMs``
    (js/packages/core/src/sync/syncFlows.ts).
    """
    global _last_published_ms
    with _published_ms_lock:
        _last_published_ms = max(int(time.time() * 1000), _last_published_ms + 1)
        return _last_published_ms


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


def new_manifest_id(key_index: bytes) -> tuple[str, bytes]:
    """Return a new manifest identifier and nonce.

    The identifier is computed as HMAC-SHA256 of ``b"manifest|" + nonce``
    using ``key_index`` as the HMAC key. The nonce is returned so it can be
    embedded inside the manifest itself.
    """

    nonce = os.urandom(16)
    digest = hmac.new(key_index, b"manifest|" + nonce, hashlib.sha256).hexdigest()
    return digest, nonce


def _manifest_event_created_at(event) -> int:
    """``created_at`` as whole seconds, across the SDK's shapes."""
    value = getattr(event, "created_at", None)
    if callable(value):
        value = value()
    if value is None:
        value = getattr(event, "timestamp", 0)
        if callable(value):
            value = value()
    if hasattr(value, "secs"):
        value = value.secs
    if callable(getattr(value, "as_secs", None)):
        value = value.as_secs()
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _manifest_event_parses(event) -> bool:
    """Is this a structurally valid manifest, as opposed to relay noise?

    Distinguishes "the newest snapshot is incomplete" -- which must fail
    loudly rather than fall back -- from "a relay handed us a junk event",
    which should simply be ignored.
    """
    try:
        data = json.loads(event.content())
        return (
            isinstance(data, dict)
            and "ver" in data
            and "algo" in data
            and isinstance(data.get("chunks"), list)
        )
    except Exception:
        return False


def _sort_manifest_events_newest_first(events: list) -> list:
    """Order manifest events newest-first, by signed publication time.

    Previously this code took whatever the relay returned first, having asked
    for ``limit(1)`` -- which hands the relay the choice of which snapshot a
    restore returns. Even ordering by ``created_at`` is not enough on its own:
    it is whole seconds, so two snapshots from the same second tie and the
    tie-break decides the outcome. ``published_ms`` lives inside the signed
    manifest, so it is both finer-grained and not something a relay can steer.

    Event id is the final tie-break: it is a hash of the event's own contents,
    giving a stable total order that no party chooses. Arrival order is never
    used.

    Must agree with the TypeScript ``fetchLatestSnapshot`` ordering.
    """

    def key(event):
        created_at = _manifest_event_created_at(event)
        order_ms = created_at * 1000
        try:
            data = json.loads(event.content())
            raw = data.get("published_ms")
            if raw is not None:
                order_ms = int(raw)
        except Exception:
            # Unparseable manifests are rejected further down; order them by
            # created_at so they do not jump the queue on the way there.
            pass
        event_id = getattr(event, "id", "")
        if callable(event_id):
            event_id = event_id()
        return (order_ms, str(event_id))

    return sorted(events, key=key, reverse=True)


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
        if isinstance(getattr(self, "manifest_index0_metadata", None), dict):
            manifest.index0 = dict(self.manifest_index0_metadata)

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

        if (
            self.current_manifest_id
            and self.current_manifest
            and getattr(self.current_manifest, "nonce", None)
        ):
            manifest_id = self.current_manifest_id
            manifest.nonce = self.current_manifest.nonce
        else:
            manifest_id, nonce = new_manifest_id(self.key_index)
            manifest.nonce = base64.b64encode(nonce).decode("utf-8")

        # Sub-second publication time, signed as part of the manifest, so a
        # restore can tell two same-second snapshots apart. See
        # Manifest.published_ms.
        manifest.published_ms = _next_published_ms()

        manifest_json = json.dumps(
            {
                "ver": manifest.ver,
                "algo": manifest.algo,
                "chunks": [meta.__dict__ for meta in manifest.chunks],
                "delta_since": manifest.delta_since,
                "nonce": manifest.nonce,
                "index0": manifest.index0,
                "published_ms": manifest.published_ms,
            }
        )

        manifest_event = (
            nostr_client.EventBuilder(nostr_client.Kind(KIND_MANIFEST), manifest_json)
            .tags([nostr_client.Tag.identifier(manifest_id)])
            .build(self.keys.public_key())
            .sign_with_keys(self.keys)
        )
        await self.client.send_event(manifest_event)
        with self._state_lock:
            self.current_manifest = manifest
            self.current_manifest_id = manifest_id
            self.current_manifest.delta_since = int(time.time())
            self._delta_events = []
        if getattr(self, "verbose_timing", False):
            duration = time.perf_counter() - start
            logger.info("publish_snapshot completed in %.2f seconds", duration)
        return manifest, manifest_id

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
                nonce=data.get("nonce"),
                index0=(
                    data.get("index0") if isinstance(data.get("index0"), dict) else None
                ),
                published_ms=(
                    int(data["published_ms"])
                    if data.get("published_ms") is not None
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

        ident = self.current_manifest_id
        f = nostr_client.Filter().author(pubkey).kind(nostr_client.Kind(KIND_MANIFEST))
        if ident:
            f = f.identifier(ident)
        f = f.limit(MANIFEST_FETCH_LIMIT)
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

        if not events and ident:
            f = (
                nostr_client.Filter()
                .author(pubkey)
                .kind(nostr_client.Kind(KIND_MANIFEST))
                .limit(MANIFEST_FETCH_LIMIT)
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

        events = _sort_manifest_events_newest_first(events)

        # Newest first, and deliberately NOT a fallback loop over older ones.
        #
        # Fetching several manifests is about taking the "which is newest"
        # decision back from the relay, not about accepting an older snapshot
        # when the newest cannot be assembled. A relay that withholds one
        # chunk of the current snapshot would otherwise walk the client
        # silently backwards through its own history, and a restore that
        # quietly returns last week's vault is indistinguishable from one that
        # worked. Refusing is recoverable; a silent downgrade is not.
        #
        # Manifests that do not parse at all are skipped rather than fatal: a
        # relay can inject any event it likes into a response, and one
        # malformed frame must not deny service to a client whose own snapshot
        # is intact. The first manifest that PARSES is the only one tried.
        for manifest_event in events:
            try:
                result = await self._fetch_chunks_with_retry(manifest_event)
            except Exception as e:  # pragma: no cover - network errors
                self.last_error = str(e)
                logger.error(
                    "Error retrieving snapshot from relays %s: %s",
                    self.relays,
                    e,
                )
                continue
            if result is not None:
                return result
            if _manifest_event_parses(manifest_event):
                # A real manifest we could not complete. Say so instead of
                # reaching further back.
                self.last_error = (
                    "The newest snapshot could not be assembled (a relay did "
                    "not return every chunk). Refusing to restore an older "
                    "snapshot silently; retry, or add another relay."
                )
                logger.error("%s", self.last_error)
                return None
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
        ident = self.current_manifest_id
        if ident is None:
            return
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
                # Republishing the manifest under the same identifier makes
                # this the newest version of it, so it needs a fresh
                # published_ms like any other publish. Omitting it would sort
                # the manifest carrying the newest delta_since BELOW the
                # snapshot it supersedes, and readers would then fetch deltas
                # from a stale watermark -- the update would simply not arrive.
                self.current_manifest.published_ms = _next_published_ms()
                manifest_json = json.dumps(
                    {
                        "ver": self.current_manifest.ver,
                        "algo": self.current_manifest.algo,
                        "chunks": [
                            meta.__dict__ for meta in self.current_manifest.chunks
                        ],
                        "delta_since": self.current_manifest.delta_since,
                        "nonce": self.current_manifest.nonce,
                        "index0": self.current_manifest.index0,
                        "published_ms": self.current_manifest.published_ms,
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
