/**
 * High-risk partition: on-disk format — parity with
 * src/seedpass/core/high_risk_partition_store.py and
 * src/seedpass/core/agent_secret_isolation.py.
 *
 * The idea is that some entry kinds (ssh, pgp, seed, nostr, managed_account)
 * are worth a SECOND factor beyond the master password. Their full records
 * move out of the vault index into a separate encrypted file, and the index
 * keeps only a stub naming the partition. Reading one back needs the factor.
 *
 * This module is the file format only, so a partition written by either
 * implementation opens in the other. It deliberately holds no session state:
 * see the note on `partitionKeyTag` for why that separation matters.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { base64, base64url } from "@scure/base";
import { fernetDecrypt, fernetEncrypt } from "./fernet.js";
import { bytesToHex, utf8 } from "../util/bytes.js";
import { entrySchema, type Entry } from "../schema/entries.js";

export const PARTITION_FILENAME = "seedpass_high_risk_entries.json.enc";
export const PARTITION_SCHEMA_VERSION = 1;
export const PARTITION_ENVELOPE_VERSION = 1;
export const PARTITION_KDF_ITERATIONS = 200_000;

/** Entry kinds treated as high risk by default, matching Python's policy. */
export const HIGH_RISK_KINDS = ["ssh", "pgp", "seed", "nostr", "managed_account"] as const;

export class HighRiskError extends Error {
  constructor(
    readonly reason: string,
    message?: string,
  ) {
    super(message ?? reason);
    this.name = "HighRiskError";
  }
}

/**
 * The identifier for a partition key.
 *
 * IMPORTANT: this value is not merely an identifier — `partitionFileKey`
 * derives the partition's encryption key from it, so anything holding the tag
 * can decrypt the partition without the factor. It must never be written to
 * disk, logged, or returned over an API. Python stores it in
 * `agent_high_risk_unlock.json` during an unlock session, which is why the
 * TypeScript port keeps unlock state in the agent's memory instead; see
 * docs and `agent.ts`.
 */
export function partitionKeyTag(partitionKey: string): string {
  return bytesToHex(sha256(utf8(partitionKey)));
}

/** The Fernet key for the partition file, derived from the tag. */
function partitionFileKey(tag: string): Uint8Array {
  return sha256(utf8(tag));
}

export interface PartitionPayload {
  schema_version: number;
  partition: string;
  updated_at_utc: number;
  entries: Record<string, Record<string, unknown>>;
}

/** Decrypt a partition file's bytes into its entry map. */
export async function decryptPartition(
  blob: Uint8Array,
  tag: string,
): Promise<Record<string, Record<string, unknown>>> {
  let plaintext: Uint8Array;
  try {
    plaintext = await fernetDecrypt(partitionFileKey(tag), blob);
  } catch {
    // The cause is dropped deliberately, not carelessly: the reason a Fernet
    // decrypt failed distinguishes "wrong key" from "corrupt blob", and
    // surfacing that difference hands a caller an oracle for probing the
    // factor. One reason string, the same one Python raises so callers can
    // branch on it, and nothing about which way it failed.
    throw new HighRiskError("invalid_partition_key_tag", "invalid_partition_key_tag");
  }
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new HighRiskError("invalid_partition_payload", "partition payload is not JSON");
  }
  if (typeof data !== "object" || data === null) return {};
  const entries = (data as Record<string, unknown>)["entries"];
  if (typeof entries !== "object" || entries === null || Array.isArray(entries)) return {};
  const out: Record<string, Record<string, unknown>> = {};
  for (const [k, v] of Object.entries(entries)) {
    if (typeof v === "object" && v !== null && !Array.isArray(v)) {
      out[String(k)] = v as Record<string, unknown>;
    }
  }
  return out;
}

/**
 * Encrypt an entry map as a partition file.
 *
 * The JSON is serialized with sorted keys and no whitespace, matching
 * Python's `json.dumps(..., sort_keys=True, separators=(",", ":"))` — not for
 * byte-identical output (the Fernet IV is random) but so the plaintext is
 * canonical in both implementations.
 */
export async function encryptPartition(
  entries: Record<string, Record<string, unknown>>,
  tag: string,
  options: { updatedAt?: number } = {},
): Promise<Uint8Array> {
  const payload: PartitionPayload = {
    schema_version: PARTITION_SCHEMA_VERSION,
    partition: "high_risk",
    updated_at_utc: options.updatedAt ?? Date.now() / 1000,
    entries,
  };
  // Sorted keys at every level, no whitespace — JSON.stringify's
  // replacer-array only sorts the top level, so this is done explicitly.
  return utf8(await fernetEncrypt(partitionFileKey(tag), utf8(stableStringify(payload))));
}

/** JSON with every object's keys sorted, matching Python's sort_keys=True. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`,
  );
  return `{${parts.join(",")}}`;
}

// ---------------------------------------------------------------- envelope

export interface PartitionEnvelope {
  version: number;
  kdf: string;
  iterations: number;
  salt_b64: string;
  wrapped_partition_key: string;
}

function wrappingKey(factor: string, salt: Uint8Array, iterations: number): Uint8Array {
  // Python derives 32 raw bytes then base64url-encodes them, and hands that
  // ASCII to Fernet(), which base64url-DECODES it back. So the effective key
  // is the raw 32 bytes; the round trip is a no-op that must not be
  // reproduced literally or the key would be the ASCII of the encoding.
  return pbkdf2(sha256, utf8(factor), salt, { c: iterations, dkLen: 32 });
}

/** Wrap a freshly generated partition key under the factor. */
export async function buildPartitionEnvelope(
  partitionKey: string,
  factor: string,
  options: { salt?: Uint8Array; iterations?: number } = {},
): Promise<PartitionEnvelope> {
  const salt = options.salt ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iterations = options.iterations ?? PARTITION_KDF_ITERATIONS;
  const wrapped = await fernetEncrypt(
    wrappingKey(factor, salt, iterations),
    utf8(partitionKey),
  );
  return {
    version: PARTITION_ENVELOPE_VERSION,
    kdf: "pbkdf2-sha256",
    iterations,
    salt_b64: base64.encode(salt),
    wrapped_partition_key: wrapped,
  };
}

/** Recover the partition key from an envelope, or throw with Python's reason. */
export async function unwrapPartitionKey(
  // Accepts either the typed envelope or a raw parsed JSON object, because
  // callers get one from disk and the other from buildPartitionEnvelope.
  envelope: PartitionEnvelope | Record<string, unknown>,
  factor: string,
): Promise<string> {
  const fields = envelope as Record<string, unknown>;
  if (Number(fields["version"] ?? 0) !== PARTITION_ENVELOPE_VERSION) {
    throw new HighRiskError("unsupported_partition_envelope_version");
  }
  const saltB64 = String(fields["salt_b64"] ?? "");
  const wrapped = String(fields["wrapped_partition_key"] ?? "");
  const iterations = Number(fields["iterations"] ?? PARTITION_KDF_ITERATIONS);
  if (!saltB64 || !wrapped || !Number.isFinite(iterations) || iterations < 1) {
    throw new HighRiskError("invalid_partition_envelope");
  }
  const key = wrappingKey(factor, base64.decode(saltB64), iterations);
  try {
    return new TextDecoder().decode(await fernetDecrypt(key, wrapped));
  } catch {
    throw new HighRiskError("high_risk_factor_invalid");
  }
}

/** A new random partition key, in the form Python generates (a Fernet key). */
export function generatePartitionKey(): string {
  return base64url.encode(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The stub left in the vault index when an entry moves to the partition.
 *
 * Deliberately carries only what a listing needs — kind, label, archived —
 * so an index read without the factor discloses that a high-risk entry
 * exists, and nothing about it.
 */
export function partitionStub(
  id: string,
  entry: Record<string, unknown>,
  kind: string,
  now: number,
): Record<string, unknown> {
  return {
    type: kind,
    kind,
    index: Number(entry["index"] ?? id),
    label: String(entry["label"] ?? ""),
    archived: Boolean(entry["archived"] ?? false),
    partition: "high_risk",
    partition_ref: id,
    modified_ts: Number(entry["modified_ts"] ?? Math.floor(now)),
  };
}

/**
 * Validate one decrypted partition record before anything derives from it.
 *
 * WHY THIS EXISTS
 *
 * `decryptPartition` proves the file is AUTHENTIC -- it decrypts under the
 * partition key, and Fernet carries an HMAC, so nobody without the factor
 * wrote it. It says nothing about the record's SHAPE: it checks only that
 * each value is an object. Callers then asserted the result into `Entry` and
 * handed it to materializeSecret.
 *
 * That was the one place in the vault where a record reached secret
 * derivation without passing the schema. Everything arriving through the
 * index goes through parseVaultIndex; the partition path did not, and the
 * partition is where the ssh keys, pgp keys and seeds live. Python writes
 * these files too and validates nothing, so a shape divergence between the
 * implementations -- a renamed field, a kind added on one side -- would not
 * have raised anything here. It would have derived from whatever fields it
 * found and returned a confidently wrong secret, which is worse than an
 * error by a wide margin.
 *
 * Validated per RECORD rather than for the whole file on read, so one odd
 * record fails one entry instead of locking the user out of every secret in
 * the partition.
 *
 * The error names the entry and nothing else. The record is the secret.
 */
export function parsePartitionRecord(
  id: string,
  raw: Record<string, unknown>,
): Entry {
  const result = entrySchema.safeParse(raw);
  if (!result.success) {
    throw new HighRiskError(
      "invalid_partition_record",
      `the high-risk record for entry ${id} does not match any known entry ` +
        `shape, so deriving from it could return the wrong secret`,
    );
  }
  return result.data;
}

/** Is this index entry a stub standing in for a partitioned record? */
export function isPartitionStub(entry: Record<string, unknown>): boolean {
  return String(entry["partition"] ?? "") === "high_risk";
}
