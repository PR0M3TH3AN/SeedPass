/**
 * Application directory and profile (fingerprint) management, compatible
 * with the Python layout so seedpass-js can open an existing ~/.seedpass:
 *
 *   ~/.seedpass/fingerprints.json        {fingerprints, last_used, names}
 *   ~/.seedpass/<FP>/parent_seed.enc     kdf/ct wrapper, password key
 *   ~/.seedpass/<FP>/seedpass_entries_db.json.enc   index key
 *   ~/.seedpass/<FP>/seedpass_config.json.enc       index key
 */

import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { base64url } from "@scure/base";
import {
  generateFingerprint,
  deriveKeyFromPassword,
  deriveKeyFromPasswordArgon2,
  deriveIndexKeyBytes,
  decryptPayload,
  encryptV3,
  parseEncryptedFile,
  utf8,
  type KdfConfig,
} from "@seedpass/core";

export const INDEX_FILENAME = "seedpass_entries_db.json.enc";
export const CONFIG_FILENAME = "seedpass_config.json.enc";
export const PARENT_SEED_FILENAME = "parent_seed.enc";

export interface FingerprintsFile {
  fingerprints: string[];
  last_used: string | null;
  names: Record<string, string>;
}

export function resolveAppDir(override?: string): string {
  return override ?? process.env["SEEDPASS_APP_DIR"] ?? join(homedir(), ".seedpass");
}

export class AppDir {
  constructor(public readonly root: string) {}

  private get fingerprintsPath(): string {
    return join(this.root, "fingerprints.json");
  }

  profileDir(fingerprint: string): string {
    return join(this.root, fingerprint);
  }

  async readFingerprints(): Promise<FingerprintsFile> {
    try {
      const raw = JSON.parse(await readFile(this.fingerprintsPath, "utf8")) as Partial<FingerprintsFile>;
      return {
        fingerprints: raw.fingerprints ?? [],
        last_used: raw.last_used ?? null,
        names: raw.names ?? {},
      };
    } catch {
      return { fingerprints: [], last_used: null, names: {} };
    }
  }

  async writeFingerprints(data: FingerprintsFile): Promise<void> {
    await mkdir(this.root, { recursive: true });
    // indent=4 matches the Python writer
    await writeFile(this.fingerprintsPath, JSON.stringify(data, null, 4), { mode: 0o600 });
  }

  /** Create a profile from a mnemonic; returns its fingerprint. */
  async createProfile(mnemonic: string, password: string, name?: string): Promise<string> {
    const fingerprint = generateFingerprint(mnemonic);
    const data = await this.readFingerprints();
    if (data.fingerprints.includes(fingerprint)) {
      throw new Error(`profile ${fingerprint} already exists`);
    }
    const dir = this.profileDir(fingerprint);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    // parent_seed.enc: kdf/ct wrapper around a V3 blob under the password key
    const seedKey = base64url.decode(deriveKeyFromPassword(password, fingerprint));
    const ct = await encryptV3(seedKey, utf8(mnemonic));
    const kdf: KdfConfig = {
      name: "pbkdf2-sha256",
      version: 1,
      params: { iterations: 100000 },
      salt_b64: "",
    };
    const wrapper = JSON.stringify({
      kdf,
      ct: Buffer.from(ct).toString("base64"),
    });
    await writeFile(join(dir, PARENT_SEED_FILENAME), wrapper, { mode: 0o600 });

    // empty entries index under the index key
    const indexKey = deriveIndexKeyBytes(mnemonic);
    const emptyIndex = { schema_version: 4, entries: {} };
    await writeFile(
      join(dir, INDEX_FILENAME),
      await encryptV3(indexKey, utf8(JSON.stringify(emptyIndex))),
      { mode: 0o600 },
    );

    data.fingerprints.push(fingerprint);
    data.last_used = fingerprint;
    if (name) data.names[fingerprint] = name;
    await this.writeFingerprints(data);
    return fingerprint;
  }

  async removeProfile(fingerprint: string): Promise<void> {
    const data = await this.readFingerprints();
    if (!data.fingerprints.includes(fingerprint)) {
      throw new Error(`no profile ${fingerprint}`);
    }
    await rm(this.profileDir(fingerprint), { recursive: true, force: true });
    data.fingerprints = data.fingerprints.filter((f) => f !== fingerprint);
    delete data.names[fingerprint];
    if (data.last_used === fingerprint) {
      data.last_used = data.fingerprints[0] ?? null;
    }
    await this.writeFingerprints(data);
  }

  async switchProfile(fingerprint: string): Promise<void> {
    const data = await this.readFingerprints();
    if (!data.fingerprints.includes(fingerprint)) {
      throw new Error(`no profile ${fingerprint}`);
    }
    data.last_used = fingerprint;
    await this.writeFingerprints(data);
  }

  /** Decrypt a profile's parent seed with its master password. */
  async decryptParentSeed(fingerprint: string, password: string): Promise<string> {
    const path = join(this.profileDir(fingerprint), PARENT_SEED_FILENAME);
    if (!existsSync(path)) throw new Error(`no parent seed file for ${fingerprint}`);
    const blob = new Uint8Array(await readFile(path));
    const { kdf, ciphertext } = parseEncryptedFile(blob);

    const candidates: Uint8Array[] = [];
    if (kdf.name === "argon2id" && kdf.salt_b64) {
      candidates.push(base64url.decode(deriveKeyFromPasswordArgon2(password, kdf)));
    }
    const iterations = Number((kdf.params as { iterations?: number }).iterations ?? 0);
    for (const iters of [...(iterations ? [iterations] : []), 100_000, 50_000]) {
      candidates.push(base64url.decode(deriveKeyFromPassword(password, fingerprint, iters)));
    }
    let lastError: unknown;
    for (const key of candidates) {
      try {
        const plain = await decryptPayload(key, ciphertext);
        return new TextDecoder().decode(plain).trim();
      } catch (e) {
        lastError = e;
      }
    }
    throw new Error(`could not decrypt parent seed (wrong password?): ${String(lastError)}`);
  }
}
