/**
 * Nostr sync parity: snapshot chunking/reassembly, manifest identity,
 * deterministic conflict merge, tombstones, and full delta replay.
 * Expected values are Python-generated fixtures.
 */

import { describe, expect, it } from "vitest";
import { base64 } from "@scure/base";
import {
  nostrSnapshot,
  syncMergeCases,
  deltaReplay,
  mnemonics,
} from "@seedpass/test-vectors";
import {
  parseManifest,
  prepareSnapshot,
  reassembleSnapshot,
  gzipDecompress,
  deriveKeyIndex,
  manifestIdFromNonce,
  mergeIndexPayloads,
  decryptV3,
  deriveIndexKeyBytes,
  bytesToHex,
  hexToBytes,
  ChunkVerificationError,
  KIND_MANIFEST,
  KIND_SNAPSHOT_CHUNK,
  KIND_DELTA,
} from "@seedpass/core";

describe("snapshot chunking", () => {
  it("uses the agreed event kinds", () => {
    expect(KIND_MANIFEST).toBe(nostrSnapshot.event_kinds.manifest);
    expect(KIND_SNAPSHOT_CHUNK).toBe(nostrSnapshot.event_kinds.snapshot_chunk);
    expect(KIND_DELTA).toBe(nostrSnapshot.event_kinds.delta);
  });

  it("parses the Python manifest JSON", () => {
    const manifest = parseManifest(nostrSnapshot.manifest_json);
    expect(manifest.ver).toBe(1);
    expect(manifest.algo).toBe("gzip");
    expect(manifest.chunks).toEqual(nostrSnapshot.chunk_metas);
    expect(manifest.nonce).toBe(nostrSnapshot.manifest_nonce_b64);
  });

  it("reassembles and decompresses the Python-produced chunks", async () => {
    const manifest = parseManifest(nostrSnapshot.manifest_json);
    const chunks = nostrSnapshot.chunks_b64.map((c) => base64.decode(c));
    const encrypted = await reassembleSnapshot(manifest, chunks);
    expect(base64.encode(encrypted)).toBe(nostrSnapshot.encrypted_b64);
  });

  it("rejects a corrupted chunk", async () => {
    const manifest = parseManifest(nostrSnapshot.manifest_json);
    const chunks = nostrSnapshot.chunks_b64.map((c) => base64.decode(c));
    chunks[0]![0]! ^= 0x01;
    await expect(reassembleSnapshot(manifest, chunks)).rejects.toThrow(
      ChunkVerificationError,
    );
  });

  it("roundtrips its own compression and hashes chunks like Python", async () => {
    const encrypted = base64.decode(nostrSnapshot.encrypted_b64);
    const { manifest, chunks } = await prepareSnapshot(encrypted, nostrSnapshot.chunk_limit);
    expect(manifest.chunks.length).toBe(chunks.length);
    expect(manifest.chunks[0]!.id).toBe("seedpass-chunk-0000");
    const restored = await reassembleSnapshot(manifest, chunks);
    expect(base64.encode(restored)).toBe(nostrSnapshot.encrypted_b64);
  });

  it("decompresses Python gzip output directly", async () => {
    const compressed = base64.decode(nostrSnapshot.compressed_b64);
    const out = await gzipDecompress(compressed);
    expect(base64.encode(out)).toBe(nostrSnapshot.encrypted_b64);
  });

  it("derives the manifest id from key_index and nonce", () => {
    const keyIndex = deriveKeyIndex(mnemonics[nostrSnapshot.mnemonic_id]!);
    expect(bytesToHex(keyIndex)).toBe(nostrSnapshot.key_index_hex);
    const nonce = base64.decode(nostrSnapshot.manifest_nonce_b64);
    expect(manifestIdFromNonce(keyIndex, nonce)).toBe(nostrSnapshot.manifest_id);
    expect(manifestIdFromNonce(hexToBytes(nostrSnapshot.key_index_hex), nonce)).toBe(
      nostrSnapshot.manifest_id,
    );
  });
});

describe("deterministic conflict merge", () => {
  it.each(syncMergeCases)("$name", (c) => {
    const merged = mergeIndexPayloads(c.current, c.incoming, c.source_tag);
    expect(merged).toEqual(c.merged);
  });

  it("is order-insensitive for the newer-wins rule", () => {
    const a = syncMergeCases.find((c) => c.name === "newer-incoming-wins")!;
    const forward = mergeIndexPayloads(a.current, a.incoming, "t") as {
      entries: Record<string, { label: string }>;
    };
    const backward = mergeIndexPayloads(a.incoming, a.current, "t") as {
      entries: Record<string, { label: string }>;
    };
    expect(forward.entries["0"]!.label).toBe(backward.entries["0"]!.label);
  });
});

describe("delta replay", () => {
  it("replays encrypted deltas onto a snapshot to the Python final state", async () => {
    const key = deriveIndexKeyBytes(mnemonics[deltaReplay.mnemonic_id]!);
    let state: unknown = deltaReplay.snapshot_index;
    for (const b64 of deltaReplay.delta_payloads_b64) {
      const encrypted = base64.decode(b64);
      const plaintext = await decryptV3(key, encrypted);
      const incoming = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
      const digest = bytesToHex(
        (await import("@noble/hashes/sha2.js")).sha256(encrypted),
      );
      state = mergeIndexPayloads(state, incoming, digest.slice(0, 16));
    }
    expect(state).toEqual(deltaReplay.final_state);
  });
});
