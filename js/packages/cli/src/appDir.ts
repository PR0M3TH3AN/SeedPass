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
  assertValidMnemonic,
  deriveKeyFromPassword,
  deriveKeyFromPasswordArgon2,
  deriveIndexKeyBytes,
  decryptPayload,
  encryptV3,
  parseEncryptedFile,
  sha256Hex,
  hexToBytes,
  utf8,
  type KdfConfig,
} from "@seedpass/core";

/**
 * Python's ConfigManager default. Profile KDF metadata must match what the
 * Python app writes, or Python falls back to its config defaults and derives
 * a different key — making TS-created profiles unreadable there.
 */
export const DEFAULT_PBKDF2_ITERATIONS = 200_000;

/** Python's seed-KDF salt: sha256(fingerprint)[:16]. */
function seedKdfSalt(fingerprint: string): Uint8Array {
  return hexToBytes(sha256Hex(utf8(fingerprint))).slice(0, 16);
}

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
    // Reject typo'd phrases here: an invalid mnemonic still derives *a* seed,
    // so accepting one creates a vault that cannot be recovered or opened by
    // any other implementation.
    assertValidMnemonic(mnemonic, "parent seed");
    if (!password) throw new Error("a master password is required");
    const fingerprint = generateFingerprint(mnemonic);
    const data = await this.readFingerprints();
    if (data.fingerprints.includes(fingerprint)) {
      throw new Error(`profile ${fingerprint} already exists`);
    }
    const dir = this.profileDir(fingerprint);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    // parent_seed.enc: kdf/ct wrapper around a V3 blob under the password key.
    // Shape and parameters mirror PasswordManager._build_seed_kdf_config so
    // the Python implementation can open this profile.
    const salt = seedKdfSalt(fingerprint);
    const seedKey = base64url.decode(
      deriveKeyFromPassword(password, salt, DEFAULT_PBKDF2_ITERATIONS),
    );
    const ct = await encryptV3(seedKey, utf8(mnemonic));
    const kdf: KdfConfig = {
      name: "pbkdf2",
      version: 1,
      params: { iterations: DEFAULT_PBKDF2_ITERATIONS },
      salt_b64: Buffer.from(salt).toString("base64"),
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

    // Mirrors PasswordManager._derive_seed_key: argon2 when the metadata says
    // so, otherwise PBKDF2 with the recorded salt (falling back to the
    // fingerprint-derived salt) and iteration count, then legacy counts.
    const candidates: Uint8Array[] = [];
    if (kdf.name.startsWith("argon2") && kdf.salt_b64) {
      candidates.push(base64url.decode(deriveKeyFromPasswordArgon2(password, kdf)));
    }
    const recordedSalt = kdf.salt_b64
      ? new Uint8Array(Buffer.from(kdf.salt_b64, "base64"))
      : seedKdfSalt(fingerprint);
    const iterations = Number((kdf.params as { iterations?: number }).iterations ?? 0);
    const iterationCandidates = [
      ...(iterations ? [iterations] : []),
      DEFAULT_PBKDF2_ITERATIONS,
      100_000,
      50_000,
    ];
    for (const iters of iterationCandidates) {
      candidates.push(base64url.decode(deriveKeyFromPassword(password, recordedSalt, iters)));
      // Legacy files may predate the recorded salt; the fingerprint string
      // path derives the same bytes, but keep it explicit for clarity.
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
