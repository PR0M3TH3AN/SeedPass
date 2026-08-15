/**
 * High-level sync flows over a RelayPool, mirroring src/nostr/snapshot.py:
 * publish a chunked snapshot + manifest, fetch the latest snapshot with
 * chunk-hash verification, publish and replay deltas.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";
import { bytesToHex } from "../util/bytes.js";
import {
  buildChunkEvent,
  buildDeltaEvent,
  buildManifestEvent,
  signEvent,
  signerPublicKeyHex,
  type Filter,
  type NostrEvent,
} from "./events.js";
import {
  KIND_DELTA,
  KIND_MANIFEST,
  KIND_SNAPSHOT_CHUNK,
  newManifestId,
  parseManifest,
  prepareSnapshot,
  reassembleSnapshot,
  type Manifest,
} from "./snapshot.js";
import type { RelayPool } from "./relay.js";

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

export interface PublishedSnapshot {
  manifest: Manifest;
  manifestId: string;
  manifestEventId: string;
  chunkEventIds: string[];
}

/** Compress, chunk, sign, and publish a snapshot plus its manifest. */
export async function publishSnapshot(
  pool: RelayPool,
  privateKeyHex: string,
  keyIndex: Uint8Array,
  encryptedBytes: Uint8Array,
  options: { limit?: number; createdAt?: number } = {},
): Promise<PublishedSnapshot> {
  const createdAt = options.createdAt ?? nowUnix();
  const { manifest, chunks } = await prepareSnapshot(encryptedBytes, options.limit ?? 50_000);

  const chunkEventIds: string[] = [];
  for (let i = 0; i < chunks.length; i++) {
    const meta = manifest.chunks[i]!;
    const event = signEvent(
      privateKeyHex,
      buildChunkEvent(meta.id, base64.encode(chunks[i]!), createdAt),
    );
    const results = await pool.publish(event);
    if (!results.some((r) => r.ok)) {
      throw new Error(`no relay accepted chunk ${meta.id}`);
    }
    meta.event_id = event.id;
    chunkEventIds.push(event.id);
  }

  const { id: manifestId, nonce } = newManifestId(keyIndex);
  manifest.nonce = base64.encode(nonce);
  manifest.delta_since = createdAt;

  const manifestJson = JSON.stringify({
    ver: manifest.ver,
    algo: manifest.algo,
    chunks: manifest.chunks,
    delta_since: manifest.delta_since,
    nonce: manifest.nonce,
    index0: manifest.index0,
  });
  const manifestEvent = signEvent(
    privateKeyHex,
    buildManifestEvent(manifestId, manifestJson, createdAt),
  );
  const results = await pool.publish(manifestEvent);
  if (!results.some((r) => r.ok)) throw new Error("no relay accepted the manifest");

  return { manifest, manifestId, manifestEventId: manifestEvent.id, chunkEventIds };
}

export interface FetchedSnapshot {
  manifest: Manifest;
  manifestEvent: NostrEvent;
  /** Decompressed, still-encrypted vault payload. */
  encrypted: Uint8Array;
}

/** Fetch the newest manifest and all its chunks, verifying every hash. */
export async function fetchLatestSnapshot(
  pool: RelayPool,
  privateKeyHex: string,
): Promise<FetchedSnapshot | null> {
  const pubkey = signerPublicKeyHex(privateKeyHex);
  const manifests = await pool.fetch({ authors: [pubkey], kinds: [KIND_MANIFEST] });
  if (manifests.length === 0) return null;
  // Newest first. Two snapshots published within the same second tie on
  // created_at, so fall back to the order the relay returned them in
  // (later = more recently accepted); without this the restore can pick a
  // stale manifest after a same-second republish.
  const order = new Map(manifests.map((ev, i) => [ev.id, i]));
  manifests.sort(
    (a, b) => b.created_at - a.created_at || (order.get(b.id)! - order.get(a.id)!),
  );

  for (const manifestEvent of manifests) {
    let manifest: Manifest;
    try {
      manifest = parseManifest(manifestEvent.content);
    } catch {
      continue;
    }
    const chunks: Uint8Array[] = [];
    let complete = true;
    for (const meta of manifest.chunks) {
      const filter = meta.event_id
        ? { ids: [meta.event_id], authors: [pubkey], kinds: [KIND_SNAPSHOT_CHUNK] }
        : { authors: [pubkey], kinds: [KIND_SNAPSHOT_CHUNK], "#d": [meta.id], limit: 1 };
      const events = await pool.fetch(filter);
      const match = events.find(
        (ev) => bytesToHex(sha256(base64.decode(ev.content))) === meta.hash,
      );
      if (!match) {
        complete = false;
        break;
      }
      chunks.push(base64.decode(match.content));
    }
    if (!complete) continue;
    const encrypted = await reassembleSnapshot(manifest, chunks);
    return { manifest, manifestEvent, encrypted };
  }
  return null;
}

/** Publish an encrypted delta referencing the manifest event. */
export async function publishDelta(
  pool: RelayPool,
  privateKeyHex: string,
  manifestEventId: string,
  deltaBytes: Uint8Array,
  options: { createdAt?: number } = {},
): Promise<string> {
  const event = signEvent(
    privateKeyHex,
    buildDeltaEvent(manifestEventId, base64.encode(deltaBytes), options.createdAt ?? nowUnix()),
  );
  const results = await pool.publish(event);
  if (!results.some((r) => r.ok)) throw new Error("no relay accepted the delta");
  return event.id;
}

/**
 * Fetch deltas since a timestamp, sorted by created_at (replay order).
 *
 * `manifestEventId` binds the result to one snapshot lineage. Deltas carry
 * an `e` tag naming the manifest they extend; without checking it a relay
 * could replay a validly-signed delta from a different (older) lineage into
 * this restore. Callers restoring a specific snapshot must pass it.
 */
export async function fetchDeltasSince(
  pool: RelayPool,
  privateKeyHex: string,
  since: number,
  manifestEventId?: string,
): Promise<Uint8Array[]> {
  const pubkey = signerPublicKeyHex(privateKeyHex);
  const filter: Filter = { authors: [pubkey], kinds: [KIND_DELTA], since };
  if (manifestEventId) filter["#e"] = [manifestEventId];
  const events = await pool.fetch(filter);
  const bound = manifestEventId
    ? events.filter((ev) =>
        ev.tags.some((t) => t[0] === "e" && t[1] === manifestEventId),
      )
    : events;
  bound.sort((a, b) => a.created_at - b.created_at);
  return bound.map((ev) => base64.decode(ev.content));
}
