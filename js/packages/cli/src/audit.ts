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
import { atomicWrite } from "./vaultFile.js";

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

/**
 * A signed head: the record count and last signature, stored beside the log.
 *
 * Chain linkage alone only detects edits *within* the file. Deleting the log
 * (or a suffix of it) leaves a shorter file that still verifies perfectly —
 * an attacker can excise the evidence of their own access. The head pins the
 * expected length, and is itself HMAC'd so it cannot simply be rewritten
 * without the key.
 */
interface AuditHead {
  count: number;
  last_sig: string;
  mac: string;
}

export class AuditLog {
  private lastSig = GENESIS;
  private count = 0;
  private loaded = false;

  constructor(
    private readonly path: string,
    private readonly key: Uint8Array,
  ) {}

  private get headPath(): string {
    return `${this.path}.head`;
  }

  private headMac(count: number, lastSig: string): string {
    return hmacSha256Hex(this.key, utf8(`seedpass-audit-head|${count}|${lastSig}`));
  }

  private async loadTail(): Promise<void> {
    if (this.loaded) return;
    if (!existsSync(this.path)) {
      this.loaded = true;
      return;
    }
    // Note the ordering: `loaded` is latched only after the read succeeds.
    // Latching first meant a single transient EACCES left lastSig at GENESIS
    // and the next append re-signed from genesis mid-file, breaking the
    // chain permanently.
    const lines = (await readFile(this.path, "utf8")).split("\n").filter((l) => l.trim());
    const last = lines[lines.length - 1];
    if (last) {
      try {
        this.lastSig = (JSON.parse(last) as AuditRecord).sig ?? GENESIS;
      } catch {
        // keep genesis; verify() will surface corruption
      }
    }
    this.count = lines.length;
    this.loaded = true;
  }

  async log(event: string, details: Record<string, unknown> = {}): Promise<void> {
    await this.loadTail();
    const entry = { timestamp: isoNow(), event, details };
    const payload = canonicalJson(entry);
    const sig = signPayload(this.key, this.lastSig, payload);
    await appendFile(this.path, canonicalJson({ ...entry, sig }) + "\n", { mode: 0o600 });
    this.lastSig = sig;
    this.count += 1;
    const head: AuditHead = {
      count: this.count,
      last_sig: sig,
      mac: this.headMac(this.count, sig),
    };
    await atomicWrite(this.headPath, utf8(JSON.stringify(head)));
  }

  /**
   * Verify the whole chain against the signed head.
   *
   * Returns the records, or throws at the first break — including a length
   * or head mismatch, which is what catches deletion rather than editing.
   */
  static async verify(path: string, key: Uint8Array): Promise<AuditRecord[]> {
    const headPath = `${path}.head`;
    let head: AuditHead | null = null;
    if (existsSync(headPath)) {
      try {
        head = JSON.parse(await readFile(headPath, "utf8")) as AuditHead;
      } catch {
        throw new Error("audit head is unreadable; the log cannot be trusted");
      }
      const expectedMac = hmacSha256Hex(
        key,
        utf8(`seedpass-audit-head|${head.count}|${head.last_sig}`),
      );
      if (expectedMac !== head.mac) {
        throw new Error("audit head signature mismatch; the log cannot be trusted");
      }
    }
    if (!existsSync(path)) {
      if (head && head.count > 0) {
        throw new Error(
          `audit log is missing but its head records ${head.count} entries; ` +
            `the log was deleted`,
        );
      }
      return [];
    }
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
    if (head) {
      if (records.length !== head.count) {
        throw new Error(
          `audit log has ${records.length} records but its head records ` +
            `${head.count}; ${head.count - records.length} were removed`,
        );
      }
      if (prevSig !== head.last_sig) {
        throw new Error("audit log tail does not match its signed head");
      }
    }
    return records;
  }
}
