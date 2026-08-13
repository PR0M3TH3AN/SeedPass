/**
 * Nostr snapshot model: chunking, manifests, and reassembly.
 *
 * Parity target: src/nostr/snapshot.py and backup_models.py. The encrypted
 * vault payload is gzip-compressed, split into <=limit chunks, and published
 * as kind-30071 events (base64 content, d-tag = chunk id). The manifest
 * (kind 30070) lists chunk ids/sizes/hashes; deltas are kind 30072.
 *
 * gzip uses the platform CompressionStream/DecompressionStream. Compressed
 * bytes are NOT required to match Python byte-for-byte (deflate encoders
 * differ); what must match is that either side can decompress the other's
 * output and that chunk hashes verify against the manifest that shipped them.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { mnemonicToSeedSync } from "@scure/bip39";
import { z } from "zod";
import { bytesToHex, concatBytes, utf8 } from "../util/bytes.js";

export const KIND_MANIFEST = 30070;
export const KIND_SNAPSHOT_CHUNK = 30071;
export const KIND_DELTA = 30072;

export const chunkMetaSchema = z
  .object({
    id: z.string(),
    size: z.number().int().nonnegative(),
    hash: z.string().regex(/^[0-9a-f]{64}$/),
    event_id: z.string().nullable().optional().default(null),
  })
  .loose();

export const manifestSchema = z
  .object({
    ver: z.number().int(),
    algo: z.string(),
    chunks: z.array(chunkMetaSchema),
    delta_since: z.number().int().nullable().optional().default(null),
    nonce: z.string().nullable().optional().default(null),
    index0: z.record(z.string(), z.unknown()).nullable().optional().default(null),
  })
  .loose();

export type ChunkMeta = z.infer<typeof chunkMetaSchema>;
export type Manifest = z.infer<typeof manifestSchema>;

export function parseManifest(json: string): Manifest {
  return manifestSchema.parse(JSON.parse(json));
}

async function pipeThrough(
  data: Uint8Array,
  stream: { readable: ReadableStream; writable: WritableStream },
): Promise<Uint8Array> {
  const writer = stream.writable.getWriter();
  const writeDone = writer.write(data as BufferSource).then(() => writer.close());
  const reader = stream.readable.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value as Uint8Array);
  }
  await writeDone;
  return concatBytes(...parts);
}

export async function gzipCompress(data: Uint8Array): Promise<Uint8Array> {
  return pipeThrough(data, new CompressionStream("gzip"));
}

export async function gzipDecompress(data: Uint8Array): Promise<Uint8Array> {
  return pipeThrough(data, new DecompressionStream("gzip"));
}

/** Compress and split the encrypted vault into chunks (prepare_snapshot). */
export async function prepareSnapshot(
  encryptedBytes: Uint8Array,
  limit = 50_000,
): Promise<{ manifest: Manifest; chunks: Uint8Array[] }> {
  const compressed = await gzipCompress(encryptedBytes);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < compressed.length; i += limit) {
    chunks.push(compressed.slice(i, i + limit));
  }
  const metas: ChunkMeta[] = chunks.map((chunk, i) => ({
    id: `seedpass-chunk-${String(i).padStart(4, "0")}`,
    size: chunk.length,
    hash: bytesToHex(sha256(chunk)),
    event_id: null,
  }));
  return {
    manifest: { ver: 1, algo: "gzip", chunks: metas, delta_since: null, nonce: null, index0: null },
    chunks,
  };
}

export class ChunkVerificationError extends Error {
  constructor(
    message: string,
    public readonly chunkId: string,
  ) {
    super(message);
    this.name = "ChunkVerificationError";
  }
}

/** Verify chunk hashes against the manifest and reassemble the vault bytes. */
export async function reassembleSnapshot(
  manifest: Manifest,
  chunks: Uint8Array[],
): Promise<Uint8Array> {
  if (manifest.algo !== "gzip") {
    throw new Error(`unsupported snapshot algo: ${manifest.algo}`);
  }
  if (chunks.length !== manifest.chunks.length) {
    throw new Error(
      `chunk count mismatch: manifest lists ${manifest.chunks.length}, got ${chunks.length}`,
    );
  }
  for (let i = 0; i < chunks.length; i++) {
    const meta = manifest.chunks[i]!;
    const actual = bytesToHex(sha256(chunks[i]!));
    if (actual !== meta.hash) {
      throw new ChunkVerificationError(
        `chunk ${meta.id} hash mismatch (expected ${meta.hash}, got ${actual})`,
        meta.id,
      );
    }
  }
  return gzipDecompress(concatBytes(...chunks));
}

/** key_index: HKDF chain master -> "seedpass:v1:index" (manager.py KEY_INDEX). */
export function deriveKeyIndex(mnemonic: string): Uint8Array {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = hkdf(sha256, seed, undefined, utf8("seedpass:v1:master"), 32);
  return hkdf(sha256, master, undefined, utf8("seedpass:v1:index"), 32);
}

/** Manifest identifier: HMAC-SHA256(key_index, "manifest|" + nonce), hex. */
export function manifestIdFromNonce(keyIndex: Uint8Array, nonce: Uint8Array): string {
  return bytesToHex(hmac(sha256, keyIndex, concatBytes(utf8("manifest|"), nonce)));
}

/** New manifest id with a fresh random nonce (production path). */
export function newManifestId(keyIndex: Uint8Array): { id: string; nonce: Uint8Array } {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return { id: manifestIdFromNonce(keyIndex, nonce), nonce };
}
