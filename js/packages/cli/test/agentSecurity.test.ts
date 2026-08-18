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
import { join as joinPath } from "node:path";
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

  it("rejects non-string credentials instead of coercing them", async () => {
    // String(["abc"]) === "abc", so an array credential would otherwise pass
    // a String()-based comparison unnoticed.
    for (const shaped of [[token], { t: token }, 1, true, null]) {
      const r = await rawRequest({ op: "vault-index", fingerprint: FINGERPRINT, token: shaped });
      expect(r["ok"], `token as ${JSON.stringify(shaped)} must be refused`).toBe(false);
    }
    for (const shaped of [["x"], {}, 0]) {
      const r = await rawRequest({ op: "owner-mnemonic", fingerprint: FINGERPRINT, cap: shaped });
      expect(r["ok"]).toBe(false);
    }
    const badCommand = await rawRequest({
      op: "use-sink", fingerprint: FINGERPRINT, id: "0", token,
      sink: "exec", command: "not-an-array",
    });
    expect(badCommand["ok"]).toBe(false);
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

describe("second-audit findings", () => {
  it("keeps the owner capability outside the app directory", async () => {
    // A scoped agent is given the app directory; a capability stored there
    // would hand it the escape hatch along with the socket.
    expect(daemon.capabilityPath.startsWith(appDir)).toBe(false);
    const info = await stat(daemon.capabilityPath);
    expect(info.mode & 0o077).toBe(0);
  });

  it("agent stop authenticates and does not claim success it did not get", async () => {
    const unauthenticated = await rawRequest({ op: "shutdown" });
    expect(unauthenticated["ok"]).toBe(false);
    // The daemon must still be alive and still holding the seed
    expect((await rawRequest({ op: "ping" }))["pong"]).toBe(true);
  });

  it("never returns custom_field values to a read token", async () => {
    await run(
      { SEEDPASS_MNEMONIC: MNEMONIC },
      "entry", "add", "key-value", "with-fields", "k", "v",
    );
    // Inject a hidden custom field the way a Python-side writer would
    const { openVault, saveVault } = await import("../src/vaultFile.js");
    const vaultPath = join(appDir, FINGERPRINT, "seedpass_entries_db.json.enc");
    const vault = await openVault(vaultPath, MNEMONIC);
    const target = Object.entries(vault.index.entries).find(
      ([, e]) => e.label === "with-fields",
    )!;
    (target[1] as { custom_fields?: unknown[] }).custom_fields = [
      { label: "recovery_code", value: "HIDDEN-FIELD-SECRET", is_hidden: true },
    ];
    await saveVault(vault);

    const r = await rawRequest({ op: "vault-index", fingerprint: FINGERPRINT, token });
    expect(r["ok"]).toBe(true);
    expect(JSON.stringify(r)).not.toContain("HIDDEN-FIELD-SECRET");
    const rows = r["entries"] as Array<Record<string, unknown>>;
    const row = rows.find((x) => x["label"] === "with-fields")!;
    const fields = row["custom_fields"] as Array<Record<string, unknown>>;
    expect(fields[0]!["label"]).toBe("recovery_code");
    expect(fields[0]!["has_value"]).toBe(true);
    expect(fields[0]).not.toHaveProperty("value");
  });

  it("does not disclose which entry ids exist to an unauthenticated caller", async () => {
    const existing = await rawRequest({ op: "secret", fingerprint: FINGERPRINT, id: "0" });
    const missing = await rawRequest({ op: "secret", fingerprint: FINGERPRINT, id: "9999" });
    expect(existing["ok"]).toBe(false);
    expect(missing["ok"]).toBe(false);
    // Identical denial: an enumeration oracle is an information leak
    expect(existing["error"]).toBe(missing["error"]);
  });

  it("rejects an oversized request instead of buffering it", async () => {
    const reply = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const socket = createConnection(socketPath);
      let buf = "";
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("timeout"));
      }, 10000);
      socket.on("connect", () => {
        // No newline: without a cap this grows unbounded and is rescanned.
        socket.write("x".repeat(1_000_000));
      });
      socket.on("data", (c) => {
        buf += c.toString();
        const nl = buf.indexOf("\n");
        if (nl >= 0) {
          clearTimeout(timer);
          socket.destroy();
          resolve(JSON.parse(buf.slice(0, nl)) as Record<string, unknown>);
        }
      });
      socket.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
    expect(reply["ok"]).toBe(false);
    expect(String(reply["error"])).toContain("too large");
  });

  it("clamps a token-supplied TOTP timestamp to now", async () => {
    const far = await rawRequest({
      op: "secret", fingerprint: FINGERPRINT, id: "1", token, timestamp: 4000000000,
    });
    expect(far["ok"]).toBe(false);
    expect(String(far["error"])).toMatch(/timestamp|denied/);
  });

  it("detects a truncated audit log", async () => {
    const auditPath = join(appDir, FINGERPRINT, "audit.log");
    const original = await readFile(auditPath, "utf8");
    const lines = original.split("\n").filter((l) => l.trim());
    // Excise the most recent records, as an attacker covering their tracks
    await writeFile(auditPath, lines.slice(0, Math.max(1, lines.length - 2)).join("\n") + "\n");
    const r = await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "agent", "audit-verify");
    expect(String((r.error as Error).message)).toMatch(/removed|head/);
    await writeFile(auditPath, original);
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

describe("malformed daemon input cannot corrupt held state", () => {
  // Reproduces the 2026-08-17 self-review findings, spoken to the socket
  // directly. The CLI would reject these, which is exactly why the daemon
  // must too: it treats every caller as untrusted.
  const SCRATCH_FP = "BBBBBBBBBBBBBBBB";
  let cap: string;
  beforeAll(async () => {
    cap = (await readFile(daemon.capabilityPath, "utf8")).trim();
  });

  it("a put with a non-numeric ttl is refused, and holds nothing", async () => {
    const put = await rawRequest({
      op: "put", cap, fingerprint: SCRATCH_FP, mnemonic: MNEMONIC, ttl: "abc",
    });
    expect(put["ok"]).toBe(false);
    expect(String(put["error"])).toContain("ttl");
    // A reported failure must be a real one: NaN once left the seed resident
    // and unexpiring with no audit record. The seed must not be held at all.
    const owner = await rawRequest({ op: "owner-mnemonic", cap, fingerprint: SCRATCH_FP });
    expect(owner["ok"]).toBe(false);
    expect(JSON.stringify(owner)).not.toContain("abandon");
  });

  it("token-issue refuses a bare-string scope and a non-numeric ttl without crashing", async () => {
    const strScope = await rawRequest({
      op: "token-issue", cap, fingerprint: FINGERPRINT, scopes: "reveal", ttl: 600, uses: 1,
    });
    expect(strScope["ok"]).toBe(false);
    expect(strScope["token"]).toBeUndefined();

    const badTtl = await rawRequest({
      op: "token-issue", cap, fingerprint: FINGERPRINT, scopes: ["read"], ttl: "soon", uses: 1,
    });
    expect(badTtl["ok"]).toBe(false);
    expect(String(badTtl["error"])).toContain("ttl");

    // The daemon is still answering — a raw TypeError must not have escaped.
    expect((await rawRequest({ op: "ping" }))["pong"]).toBe(true);
  });
});

describe("a use-scoped token cannot crash the agent", () => {
  it("a stdin sink to a command that exits before reading does not kill the daemon", async () => {
    // A large secret so the payload cannot fit the pipe buffer: the child
    // exits before draining it, which raised an unhandled EPIPE and took the
    // whole agent process down.
    const bigValue = "y".repeat(200_000);
    const added = JSON.parse(
      (await run(
        { SEEDPASS_MNEMONIC: MNEMONIC },
        "entry", "add", "key-value", "bulk", "k", bigValue,
      )).stdout,
    );
    const id = String(added.id);

    // A fresh token, not the shared one: earlier tests may have spent its uses.
    const useToken = JSON.parse(
      (await run(
        {}, "agent", "token-issue", "--scope", "read", "use", "--uses", "5", "--ttl", "600",
      )).stdout,
    ).token;

    const r = await rawRequest({
      op: "use-sink", fingerprint: FINGERPRINT, id, token: useToken,
      sink: "stdin", command: ["/bin/true"],
    });
    expect(r["ok"]).toBe(true);

    // The load-bearing assertions: the agent is still alive and still holding
    // the seed after a delivery that used to crash it.
    expect((await rawRequest({ op: "ping" }))["pong"]).toBe(true);
    const status = JSON.parse((await run({}, "agent", "status")).stdout);
    expect(status.map((p: { fingerprint: string }) => p.fingerprint)).toContain(FINGERPRINT);
  });
});
