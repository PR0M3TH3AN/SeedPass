/**
 * Tamper-evident audit log, chain-compatible with Python's AuditLogger:
 * each record's sig = HMAC-SHA256(key, prev_sig + canonical_payload) where
 * canonical_payload is the compact sort_keys JSON of {timestamp, event,
 * details} and the genesis prev_sig is 64 zeros. The signing key is the
 * profile's index-derivation key (KEY_INDEX), so only the seed holder can
 * extend or verify the chain.
 */

import { appendFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { canonicalJson, hmacSha256Hex, utf8 } from "@seedpass/core";

const GENESIS = "0".repeat(64);

export interface AuditRecord {
  timestamp: string;
  event: string;
  details: Record<string, unknown>;
  sig: string;
}

function isoNow(): string {
  return new Date().toISOString().replace("Z", "+00:00");
}

function signPayload(key: Uint8Array, prevSig: string, payload: string): string {
  return hmacSha256Hex(key, utf8(prevSig + payload));
}

export class AuditLog {
  private lastSig = GENESIS;
  private loaded = false;

  constructor(
    private readonly path: string,
    private readonly key: Uint8Array,
  ) {}

  private async loadTail(): Promise<void> {
    if (this.loaded) return;
    this.loaded = true;
    if (!existsSync(this.path)) return;
    const lines = (await readFile(this.path, "utf8")).split("\n").filter((l) => l.trim());
    const last = lines[lines.length - 1];
    if (last) {
      try {
        this.lastSig = (JSON.parse(last) as AuditRecord).sig ?? GENESIS;
      } catch {
        // keep genesis; verify() will surface corruption
      }
    }
  }

  async log(event: string, details: Record<string, unknown> = {}): Promise<void> {
    await this.loadTail();
    const entry = { timestamp: isoNow(), event, details };
    const payload = canonicalJson(entry);
    const sig = signPayload(this.key, this.lastSig, payload);
    await appendFile(this.path, canonicalJson({ ...entry, sig }) + "\n", { mode: 0o600 });
    this.lastSig = sig;
  }

  /** Verify the whole chain; returns records or throws at the first break. */
  static async verify(path: string, key: Uint8Array): Promise<AuditRecord[]> {
    if (!existsSync(path)) return [];
    const lines = (await readFile(path, "utf8")).split("\n").filter((l) => l.trim());
    const records: AuditRecord[] = [];
    let prevSig = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      let record: AuditRecord;
      try {
        record = JSON.parse(lines[i]!) as AuditRecord;
      } catch {
        throw new Error(`audit chain broken at line ${i + 1}: unparseable record`);
      }
      const payload = canonicalJson({
        timestamp: record.timestamp,
        event: record.event,
        details: record.details,
      });
      const expected = signPayload(key, prevSig, payload);
      if (expected !== record.sig) {
        throw new Error(`audit chain broken at line ${i + 1}: signature mismatch`);
      }
      prevSig = record.sig;
      records.push(record);
    }
    return records;
  }
}
