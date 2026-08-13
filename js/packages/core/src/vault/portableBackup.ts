/**
 * Portable encrypted profile backups.
 *
 * Parity target: src/seedpass/core/portable_backup.py, format_version 1.
 * The wrapper is plain JSON; the payload is canonical JSON of the index,
 * either plaintext ("none") or V3 AES-GCM encrypted with the index key of
 * the parent seed ("seed-only"). The checksum is SHA-256 over the canonical
 * JSON of the index and is verified on import.
 */

import { base64 } from "@scure/base";
import { z } from "zod";
import { canonicalJson, canonicalHash } from "../sync/canonical.js";
import { deriveIndexKeyBytes } from "./indexKey.js";
import { decryptPayload } from "./payload.js";
import { encryptV3 } from "./aead.js";
import { utf8 } from "../util/bytes.js";

export const PORTABLE_FORMAT_VERSION = 1;

export const portableBackupSchema = z
  .object({
    format_version: z.number().int(),
    created_at: z.number().int(),
    fingerprint: z.string(),
    encryption_mode: z.enum(["seed-only", "none"]),
    cipher: z.string(),
    checksum: z.string().regex(/^[0-9a-f]{64}$/),
    payload: z.string(),
  })
  .loose();

export type PortableBackup = z.infer<typeof portableBackupSchema>;

export class BackupImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackupImportError";
  }
}

/** Import a portable backup wrapper, returning the verified index payload. */
export async function importBackup(
  wrapperJson: string | Uint8Array,
  options: { mnemonic?: string } = {},
): Promise<Record<string, unknown>> {
  const text =
    typeof wrapperJson === "string" ? wrapperJson : new TextDecoder().decode(wrapperJson);
  let wrapper: PortableBackup;
  try {
    wrapper = portableBackupSchema.parse(JSON.parse(text));
  } catch (e) {
    throw new BackupImportError(`invalid backup wrapper: ${String(e)}`);
  }
  if (wrapper.format_version !== PORTABLE_FORMAT_VERSION) {
    throw new BackupImportError("Unsupported backup format");
  }

  const payload = base64.decode(wrapper.payload);
  let indexBytes: Uint8Array;
  if (wrapper.encryption_mode === "seed-only") {
    if (!options.mnemonic) {
      throw new BackupImportError("parent seed required for seed-only backups");
    }
    const key = deriveIndexKeyBytes(options.mnemonic);
    try {
      indexBytes = await decryptPayload(key, payload);
    } catch {
      throw new BackupImportError("failed to decrypt backup payload");
    }
  } else {
    indexBytes = payload;
  }

  let index: Record<string, unknown>;
  try {
    index = JSON.parse(new TextDecoder().decode(indexBytes)) as Record<string, unknown>;
  } catch {
    throw new BackupImportError("backup payload is not valid JSON");
  }

  if (canonicalHash(index) !== wrapper.checksum) {
    throw new BackupImportError("Checksum mismatch");
  }
  return index;
}

/** Export an index as a portable backup wrapper (format_version 1). */
export async function exportBackup(
  index: Record<string, unknown>,
  options: {
    mnemonic: string;
    fingerprint: string;
    encrypt?: boolean;
    createdAt?: number;
    /** Fixture/testing only — production draws a random nonce. */
    nonce?: Uint8Array;
  },
): Promise<PortableBackup> {
  const canonical = canonicalJson(index);
  const checksum = canonicalHash(index);
  const encrypt = options.encrypt ?? true;

  let payloadBytes: Uint8Array;
  let mode: "seed-only" | "none";
  let cipher: string;
  if (encrypt) {
    const key = deriveIndexKeyBytes(options.mnemonic);
    payloadBytes = await encryptV3(key, utf8(canonical), options.nonce);
    mode = "seed-only";
    cipher = "aes-gcm";
  } else {
    payloadBytes = utf8(canonical);
    mode = "none";
    cipher = "none";
  }

  return {
    format_version: PORTABLE_FORMAT_VERSION,
    created_at: options.createdAt ?? Math.floor(Date.now() / 1000),
    fingerprint: options.fingerprint,
    encryption_mode: mode,
    cipher,
    checksum,
    payload: base64.encode(payloadBytes),
  };
}
