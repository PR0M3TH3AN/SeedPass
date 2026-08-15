/**
 * Attacks against the agent's socket, spoken directly — not through the CLI.
 *
 * These reproduce a security review's findings: the CLI's authorization
 * checks are worthless if the daemon accepts privileged operations from any
 * local process, so every assertion here bypasses the CLI entirely.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createConnection } from "node:net";
import { mkdtemp, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import { generateFingerprint } from "@seedpass/core";
import { buildProgram, AgentDaemon, agentSocketPath, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "agent-security-pw";

let appDir: string;
let socketPath: string;
let daemon: AgentDaemon;
let token: string;

/** Speak the wire protocol directly, as a hostile local process would. */
function rawRequest(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let buffer = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("timeout"));
    }, 5000);
    socket.on("connect", () => socket.write(JSON.stringify(msg) + "\n"));
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const nl = buffer.indexOf("\n");
      if (nl >= 0) {
        clearTimeout(timer);
        socket.end();
        resolve(JSON.parse(buffer.slice(0, nl)) as Record<string, unknown>);
      }
    });
    socket.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

async function run(
  env: Record<string, string | undefined>,
  ...argv: string[]
): Promise<{ stdout: string; error?: unknown }> {
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
  appDir = await mkdtemp(join(tmpdir(), "seedpass-agentsec-"));
  socketPath = join(appDir, "agent.sock");
  process.env["SEEDPASS_AGENT_SOCK"] = socketPath;
  daemon = new AgentDaemon(socketPath, 900, appDir);
  await daemon.start();

  await run(
    { SEEDPASS_MNEMONIC: MNEMONIC, SEEDPASS_PASSWORD: PASSWORD },
    "fingerprint", "add",
  );
  await run(
    { SEEDPASS_MNEMONIC: MNEMONIC },
    "entry", "add", "key-value", "api-key", "k", "top-secret-value",
  );
  await run(
    { SEEDPASS_MNEMONIC: MNEMONIC },
    "entry", "add", "totp", "imported", "--secret", "JBSWY3DPEHPK3PXP",
  );
  await run({ SEEDPASS_MNEMONIC: undefined, SEEDPASS_PASSWORD: PASSWORD }, "vault", "unlock");

  const issued = JSON.parse(
    (await run({}, "agent", "token-issue", "--scope", "read", "use", "--uses", "50", "--ttl", "600"))
      .stdout,
  );
  token = issued.token;
});

afterAll(async () => {
  await daemon.stop();
  delete process.env["SEEDPASS_AGENT_SOCK"];
});

describe("unauthenticated socket access", () => {
  it("cannot retrieve the parent seed", async () => {
    const r = await rawRequest({ op: "owner-mnemonic", fingerprint: FINGERPRINT });
    expect(r["ok"]).toBe(false);
    expect(String(r["error"])).toContain("owner capability");
    expect(JSON.stringify(r)).not.toContain("abandon");
  });

  it("cannot issue tokens", async () => {
    const r = await rawRequest({
      op: "token-issue",
      fingerprint: FINGERPRINT,
      scopes: ["read", "use", "reveal"],
      uses: 999,
    });
    expect(r["ok"]).toBe(false);
    expect(r["token"]).toBeUndefined();
  });

  it("cannot lock, shut down, inspect status, or inject a seed", async () => {
    for (const op of ["lock", "shutdown", "status"]) {
      const r = await rawRequest({ op });
      expect(r["ok"]).toBe(false);
    }
    const injected = await rawRequest({
      op: "put",
      fingerprint: "AAAAAAAAAAAAAAAA",
      mnemonic: MNEMONIC,
    });
    expect(injected["ok"]).toBe(false);

    // The profile is still unlocked and the owner still works
    const status = JSON.parse((await run({}, "agent", "status")).stdout);
    expect(status.map((p: { fingerprint: string }) => p.fingerprint)).toContain(FINGERPRINT);
  });

  it("a wrong capability is rejected", async () => {
    const r = await rawRequest({
      op: "owner-mnemonic",
      fingerprint: FINGERPRINT,
      cap: "not-the-capability",
    });
    expect(r["ok"]).toBe(false);
  });

  it("keeps the capability file readable only by the owner", async () => {
    const info = await stat(daemon.capabilityPath);
    expect(info.mode & 0o077).toBe(0);
  });
});

describe("token holders cannot exceed their grant", () => {
  it("a read-scoped request never returns the decrypted index", async () => {
    const r = await rawRequest({ op: "vault-index", fingerprint: FINGERPRINT, token });
    expect(r["ok"]).toBe(true);
    // Redacted rows only — no raw entries map, no secret material
    expect(r["index"]).toBeUndefined();
    const serialized = JSON.stringify(r);
    expect(serialized).not.toContain("top-secret-value");
    expect(serialized).not.toContain("JBSWY3DPEHPK3PXP");
    const rows = r["entries"] as Array<Record<string, unknown>>;
    expect(rows.find((x) => x["label"] === "api-key")!["has_value"]).toBe(true);
    expect(rows.find((x) => x["label"] === "imported")!["has_secret"]).toBe(true);
  });

  it("a use-scoped request cannot pull plaintext back over the socket", async () => {
    const r = await rawRequest({
      op: "secret",
      fingerprint: FINGERPRINT,
      id: "0",
      token,
      action: "use",
    });
    expect(r["ok"]).toBe(false);
    expect(String(r["error"])).toContain("reveal");
    expect(JSON.stringify(r)).not.toContain("top-secret-value");
  });

  it("a use-sink delivery returns a receipt, not the secret", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-sec-sink-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s' "$SEEDPASS_SECRET" > "${capture}"\n`, {
      mode: 0o755,
    });
    const r = await rawRequest({
      op: "use-sink",
      fingerprint: FINGERPRINT,
      id: "0",
      token,
      sink: "exec",
      command: [script],
    });
    expect(r["ok"]).toBe(true);
    expect(JSON.stringify(r)).not.toContain("top-secret-value");
    expect(await readFile(capture, "utf8")).toBe("top-secret-value");
  });

  it("cannot use its token to reach owner operations", async () => {
    const r = await rawRequest({ op: "owner-mnemonic", fingerprint: FINGERPRINT, cap: token });
    expect(r["ok"]).toBe(false);
  });
});

describe("sink children do not inherit the vault's secrets", () => {
  it("SEEDPASS_* variables are stripped from the child environment", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-env-"));
    const capture = join(dir, "env.txt");
    const script = join(dir, "dump.sh");
    await writeFile(
      script,
      `#!/bin/sh\nenv | grep '^SEEDPASS_' | sort > "${capture}"\n`,
      { mode: 0o755 },
    );
    // Run as the owner with every sensitive variable set in the parent.
    const r = await run(
      {
        SEEDPASS_MNEMONIC: MNEMONIC,
        SEEDPASS_PASSWORD: PASSWORD,
        SEEDPASS_TOKEN: token,
      },
      "use", "api-key", "--exec", script,
    );
    expect(r.error).toBeUndefined();
    const dumped = await readFile(capture, "utf8");
    expect(dumped).toContain("SEEDPASS_SECRET=top-secret-value");
    expect(dumped).not.toContain("SEEDPASS_MNEMONIC");
    expect(dumped).not.toContain("SEEDPASS_PASSWORD");
    expect(dumped).not.toContain("SEEDPASS_TOKEN");
    expect(dumped).not.toContain("SEEDPASS_AGENT_SOCK");
  });
});

describe("locking clears derived state", () => {
  it("tokens do not survive a lock and later unlock", async () => {
    const fresh = JSON.parse(
      (await run({}, "agent", "token-issue", "--scope", "read", "--ttl", "600")).stdout,
    ).token;
    expect(
      (await rawRequest({ op: "vault-index", fingerprint: FINGERPRINT, token: fresh }))["ok"],
    ).toBe(true);

    await run({ SEEDPASS_MNEMONIC: undefined }, "vault", "lock");
    await run(
      { SEEDPASS_MNEMONIC: undefined, SEEDPASS_PASSWORD: PASSWORD },
      "vault", "unlock",
    );

    const after = await rawRequest({ op: "vault-index", fingerprint: FINGERPRINT, token: fresh });
    expect(after["ok"]).toBe(false);
    expect(String(after["error"])).toContain("unknown token");
  });
});
