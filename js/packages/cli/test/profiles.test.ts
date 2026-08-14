/**
 * Profile, config, and session-agent tests: the full unlock lifecycle with
 * no SEEDPASS_MNEMONIC in the environment — the agent is the only seed
 * source, exactly how an agent-driven workflow would run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import {
  generateFingerprint,
  sha256Hex,
  hexToBytes,
  utf8,
  encryptV3,
  deriveIndexKeyBytes,
} from "@seedpass/core";
import { buildProgram, AgentDaemon, agentSocketPath, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "profile-test-password";

let appDir: string;
let daemon: AgentDaemon;

interface RunResult {
  stdout: string;
  error?: unknown;
}

async function run(env: Record<string, string | undefined>, ...argv: string[]): Promise<RunResult> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  } catch (e) {
    error = e;
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return { stdout: out.join("\n"), error };
}

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-appdir-"));
  process.env["SEEDPASS_AGENT_SOCK"] = join(appDir, "agent.sock");
  daemon = new AgentDaemon(agentSocketPath(appDir), 900);
  await daemon.start();
});

afterAll(async () => {
  await daemon.stop();
  delete process.env["SEEDPASS_AGENT_SOCK"];
});

describe("profile lifecycle", () => {
  it("creates a Python-layout profile from env secrets", async () => {
    const r = await run(
      { SEEDPASS_MNEMONIC: MNEMONIC, SEEDPASS_PASSWORD: PASSWORD },
      "fingerprint", "add", "--name", "main",
    );
    expect(JSON.parse(r.stdout).fingerprint).toBe(FINGERPRINT);
    expect(existsSync(join(appDir, FINGERPRINT, "parent_seed.enc"))).toBe(true);
    expect(existsSync(join(appDir, FINGERPRINT, "seedpass_entries_db.json.enc"))).toBe(true);
    const meta = JSON.parse(await readFile(join(appDir, "fingerprints.json"), "utf8"));
    expect(meta).toEqual({
      fingerprints: [FINGERPRINT],
      last_used: FINGERPRINT,
      names: { [FINGERPRINT]: "main" },
    });
  });

  it("writes Python-compatible parent-seed KDF metadata", async () => {
    // Python's PasswordManager._derive_seed_key only takes the recorded
    // parameters when kdf.name is exactly "pbkdf2"; anything else makes it
    // fall back to its config defaults and derive a different key, leaving
    // TS-created profiles unopenable there.
    const wrapper = JSON.parse(
      await readFile(join(appDir, FINGERPRINT, "parent_seed.enc"), "utf8"),
    ) as { kdf: { name: string; params: { iterations: number }; salt_b64: string } };
    expect(wrapper.kdf.name).toBe("pbkdf2");
    expect(wrapper.kdf.params.iterations).toBe(200000);
    // salt = sha256(fingerprint)[:16], as Python computes it
    const expectedSalt = Buffer.from(
      hexToBytes(sha256Hex(utf8(FINGERPRINT))).slice(0, 16),
    ).toString("base64");
    expect(wrapper.kdf.salt_b64).toBe(expectedSalt);
  });

  it("refuses an invalid mnemonic instead of creating an unrecoverable vault", async () => {
    // Valid words, wrong checksum. BIP-39 seed derivation would happily
    // accept it and produce a different vault that nothing can recover.
    const bogus = "gaze stereo trend brown chunk hero pole width once tent lift bird";
    const r = await run(
      { SEEDPASS_MNEMONIC: bogus, SEEDPASS_PASSWORD: "x" },
      "fingerprint", "add", "--name", "should-not-exist",
    );
    expect(String((r.error as Error).message)).toContain("valid BIP-39");
    const meta = JSON.parse(await readFile(join(appDir, "fingerprints.json"), "utf8"));
    expect(meta.fingerprints).toHaveLength(1);
  });

  it("lists and switches profiles", async () => {
    const r = await run({}, "fingerprint", "list");
    expect(JSON.parse(r.stdout)).toEqual([
      { fingerprint: FINGERPRINT, name: "main", current: true },
    ]);
  });
});

describe("agent unlock lifecycle (no mnemonic in env)", () => {
  it("locked vault refuses access with a helpful error", async () => {
    const r = await run({ SEEDPASS_MNEMONIC: undefined }, "entry", "list");
    expect(String((r.error as Error).message)).toContain("vault is locked");
  });

  it("vault unlock hands the seed to the agent using only the password", async () => {
    const r = await run(
      { SEEDPASS_MNEMONIC: undefined, SEEDPASS_PASSWORD: PASSWORD },
      "vault", "unlock", "--ttl", "60",
    );
    const row = JSON.parse(r.stdout);
    expect(row.unlocked).toBe(FINGERPRINT);
    expect(row.expires_at).toBeGreaterThan(Date.now() / 1000);
  });

  it("profile vault opens via the agent, no env mnemonic, no --vault", async () => {
    const list = await run({ SEEDPASS_MNEMONIC: undefined }, "entry", "list");
    expect(JSON.parse(list.stdout)).toEqual([]);

    const add = await run(
      { SEEDPASS_MNEMONIC: undefined },
      "entry", "add", "key-value", "agent-made", "k", "agent-value",
    );
    expect(JSON.parse(add.stdout).ref).toBe("sp://entry/0");
    expect(add.stdout).not.toContain("agent-value");

    const reveal = await run(
      { SEEDPASS_MNEMONIC: undefined },
      "entry", "reveal", "agent-made",
    );
    expect(reveal.stdout).toBe("agent-value");
  });

  it("agent status shows the unlocked profile; lock drops it", async () => {
    const status = await run({}, "agent", "status");
    expect(JSON.parse(status.stdout).map((p: { fingerprint: string }) => p.fingerprint)).toEqual([
      FINGERPRINT,
    ]);

    const lock = await run({ SEEDPASS_MNEMONIC: undefined }, "vault", "lock");
    expect(JSON.parse(lock.stdout).locked).toBe(1);

    const denied = await run({ SEEDPASS_MNEMONIC: undefined }, "entry", "list");
    expect(String((denied.error as Error).message)).toContain("vault is locked");
  });
});

describe("config file compatibility", () => {
  it("reads a config written in Python's kdf/ct wrapper format", async () => {
    // Python's EncryptionManager.save_json_data wraps ciphertext in a JSON
    // envelope; TS writes it bare. Reading must handle both.
    const key = deriveIndexKeyBytes(MNEMONIC);
    const inner = await encryptV3(key, utf8(JSON.stringify({ clipboard_clear_delay: 99 })));
    const wrapped = JSON.stringify({
      kdf: { name: "argon2id", version: 1, params: {}, salt_b64: "" },
      ct: Buffer.from(inner).toString("base64"),
    });
    await writeFile(join(appDir, FINGERPRINT, "seedpass_config.json.enc"), wrapped);

    const r = await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "config", "get");
    expect(JSON.parse(r.stdout).clipboard_clear_delay).toBe(99);
  });
});

describe("config", () => {
  it("returns defaults, persists sets, and redacts hashes", async () => {
    const env = { SEEDPASS_MNEMONIC: MNEMONIC };
    const defaults = JSON.parse((await run(env, "config", "get")).stdout);
    expect(defaults.relays).toHaveLength(3);
    expect(defaults.kdf_iterations).toBe(200000);

    await run(env, "config", "set", "clipboard_clear_delay", "10");
    await run(env, "config", "set", "relays", '["wss://relay.example"]');
    const after = JSON.parse((await run(env, "config", "get")).stdout);
    expect(after.clipboard_clear_delay).toBe(10);
    expect(after.relays).toEqual(["wss://relay.example"]);

    await run(env, "config", "set", "pin_hash", "supersecret");
    const redacted = JSON.parse((await run(env, "config", "get", "pin_hash")).stdout);
    expect(redacted.pin_hash).toBe("<redacted>");
  });
});
