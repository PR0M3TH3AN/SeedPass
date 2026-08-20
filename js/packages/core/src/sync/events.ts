/**
 * Nostr event protocol layer: NIP-01 event ids, BIP-340 signing/verify, and
 * client-relay message framing. Transport-agnostic — the WebSocket relay
 * adapter builds on this but lives with the interface milestones.
 *
 * Cross-implementation fixtures come from the Python side's rust-nostr
 * (nostr_sdk); TS-computed ids must match theirs exactly.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8 } from "../util/bytes.js";
import { KIND_DELTA, KIND_MANIFEST, KIND_SNAPSHOT_CHUNK } from "./snapshot.js";

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export type UnsignedEvent = Omit<NostrEvent, "id" | "sig" | "pubkey">;

/**
 * NIP-01 string escaping for the id serialization: exactly \n \" \\ \r \t
 * \b \f are escaped; every other character (including other control chars
 * and non-ASCII) is included verbatim as UTF-8.
 */
function nip01EscapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    switch (ch) {
      case "\n": out += "\\n"; break;
      case '"': out += '\\"'; break;
      case "\\": out += "\\\\"; break;
      case "\r": out += "\\r"; break;
      case "\t": out += "\\t"; break;
      case "\b": out += "\\b"; break;
      case "\f": out += "\\f"; break;
      default: out += ch;
    }
  }
  return out + '"';
}

/** The exact byte sequence NIP-01 hashes: [0,pubkey,created_at,kind,tags,content]. */
export function serializeEventForId(
  pubkey: string,
  createdAt: number,
  kind: number,
  tags: string[][],
  content: string,
): string {
  const tagsJson =
    "[" +
    tags.map((tag) => "[" + tag.map(nip01EscapeString).join(",") + "]").join(",") +
    "]";
  return `[0,${nip01EscapeString(pubkey)},${createdAt},${kind},${tagsJson},${nip01EscapeString(content)}]`;
}

export function computeEventId(
  pubkey: string,
  createdAt: number,
  kind: number,
  tags: string[][],
  content: string,
): string {
  return bytesToHex(sha256(utf8(serializeEventForId(pubkey, createdAt, kind, tags, content))));
}

export function signerPublicKeyHex(privateKeyHex: string): string {
  return bytesToHex(schnorr.getPublicKey(hexToBytes(privateKeyHex)));
}

/** Sign an event with a secp256k1 private key (x-only pubkey, BIP-340 sig). */
export function signEvent(privateKeyHex: string, unsigned: UnsignedEvent): NostrEvent {
  const priv = hexToBytes(privateKeyHex);
  const pubkey = bytesToHex(schnorr.getPublicKey(priv));
  const id = computeEventId(
    pubkey,
    unsigned.created_at,
    unsigned.kind,
    unsigned.tags,
    unsigned.content,
  );
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), priv));
  return { id, pubkey, ...unsigned, sig };
}

/** Verify an event's id derivation and BIP-340 signature. */
/**
 * Structural validation of an event received from a relay.
 *
 * The wire is untrusted: `parseRelayMessage` casts whatever JSON arrived, so
 * types must be checked before anything reads them. `created_at` in
 * particular is interpolated into the id preimage and used for ordering —
 * `1e999` parses to Infinity and would sort ahead of every real event
 * forever, and a string collapses comparisons to NaN.
 */
export function isWellFormedEvent(event: unknown): event is NostrEvent {
  if (typeof event !== "object" || event === null) return false;
  const e = event as Record<string, unknown>;
  if (typeof e["id"] !== "string" || !/^[0-9a-f]{64}$/.test(e["id"])) return false;
  if (typeof e["pubkey"] !== "string" || !/^[0-9a-f]{64}$/.test(e["pubkey"])) return false;
  if (typeof e["sig"] !== "string" || !/^[0-9a-f]{128}$/.test(e["sig"])) return false;
  if (typeof e["content"] !== "string") return false;
  if (
    typeof e["created_at"] !== "number" ||
    !Number.isSafeInteger(e["created_at"]) ||
    e["created_at"] < 0
  ) {
    return false;
  }
  if (typeof e["kind"] !== "number" || !Number.isSafeInteger(e["kind"])) return false;
  const tags = e["tags"];
  if (!Array.isArray(tags)) return false;
  return tags.every((t) => Array.isArray(t) && t.every((v) => typeof v === "string"));
}

/**
 * Does an event actually satisfy the filter it was requested with?
 *
 * A relay is asked for a filter, it is not obliged to honour it. Without
 * this check, `fetch` accepts an event signed by any key at all — the
 * signature only proves internal consistency, not authorship by the pubkey
 * we asked for.
 */
export function eventMatchesFilter(event: NostrEvent, filter: Filter): boolean {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  if (filter.until !== undefined && event.created_at > filter.until) return false;
  for (const tagFilter of ["#d", "#e"] as const) {
    const wanted = filter[tagFilter];
    if (wanted) {
      const name = tagFilter[1]!;
      const values = event.tags.filter((t) => t[0] === name).map((t) => t[1]);
      if (!wanted.some((w) => values.includes(w))) return false;
    }
  }
  return true;
}

export function verifyEvent(event: NostrEvent): boolean {
  if (!isWellFormedEvent(event)) return false;
  const expectedId = computeEventId(
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  );
  if (expectedId !== event.id) return false;
  try {
    return schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
  } catch {
    return false;
  }
}

// --- SeedPass event builders (parity: nostr/snapshot.py EventBuilder use) ---

export function buildChunkEvent(
  chunkId: string,
  contentB64: string,
  createdAt: number,
): UnsignedEvent {
  return {
    kind: KIND_SNAPSHOT_CHUNK,
    tags: [["d", chunkId]],
    content: contentB64,
    created_at: createdAt,
  };
}

export function buildManifestEvent(
  manifestId: string,
  manifestJson: string,
  createdAt: number,
): UnsignedEvent {
  return {
    kind: KIND_MANIFEST,
    tags: [["d", manifestId]],
    content: manifestJson,
    created_at: createdAt,
  };
}

export function buildDeltaEvent(
  manifestEventId: string,
  contentB64: string,
  createdAt: number,
): UnsignedEvent {
  return {
    kind: KIND_DELTA,
    tags: [["e", manifestEventId]],
    content: contentB64,
    created_at: createdAt,
  };
}

// --- NIP-01 client/relay message framing ---

export interface Filter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  "#d"?: string[];
  "#e"?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

export function reqMessage(subscriptionId: string, ...filters: Filter[]): string {
  return JSON.stringify(["REQ", subscriptionId, ...filters]);
}

export function eventMessage(event: NostrEvent): string {
  return JSON.stringify(["EVENT", event]);
}

export function closeMessage(subscriptionId: string): string {
  return JSON.stringify(["CLOSE", subscriptionId]);
}

export type RelayMessage =
  | { type: "EVENT"; subscriptionId: string; event: NostrEvent }
  | { type: "EOSE"; subscriptionId: string }
  | { type: "OK"; eventId: string; accepted: boolean; message: string }
  | { type: "NOTICE"; message: string }
  | { type: "CLOSED"; subscriptionId: string; message: string };

export function parseRelayMessage(raw: string): RelayMessage {
  const arr = JSON.parse(raw) as unknown[];
  if (!Array.isArray(arr) || typeof arr[0] !== "string") {
    throw new Error("malformed relay message");
  }
  switch (arr[0]) {
    case "EVENT":
      return { type: "EVENT", subscriptionId: String(arr[1]), event: arr[2] as NostrEvent };
    case "EOSE":
      return { type: "EOSE", subscriptionId: String(arr[1]) };
    case "OK":
      return {
        type: "OK",
        eventId: String(arr[1]),
        accepted: Boolean(arr[2]),
        message: String(arr[3] ?? ""),
      };
    case "NOTICE":
      return { type: "NOTICE", message: String(arr[1] ?? "") };
    case "CLOSED":
      return { type: "CLOSED", subscriptionId: String(arr[1]), message: String(arr[2] ?? "") };
    default:
      throw new Error(`unknown relay message type: ${arr[0]}`);
  }
}
