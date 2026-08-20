/**
 * Attacks against the agent's socket, spoken directly — not through the CLI.
 *
 * These reproduce a security review's findings: the CLI's authorization
 * checks are worthless if the daemon accepts privileged operations from any
 * local process, so every assertion here bypasses the CLI entirely.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createConnection } from "node:net";
import { mkdtemp, readFile, writeFile, stat, mkdir } from "node:fs/promises";
import { join as joinPath } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import { encryptV3, deriveIndexKeyBytes, utf8 } from "@seedpass/core";
import { generateFingerprint } from "@seedpass/core";
import {
  buildProgram,
  AgentDaemon,
  AgentClient,
  agentSocketPath,
  INDEX_FILENAME,
  type ProgramIo,
} from "../src/index.js";

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

  /**
   * `put` is the only way a fingerprint enters `held`, and every later handler
   * joins that string onto a path — the vault it opens, the audit log it
   * writes. The CLI validates the format before the daemon ever sees it,
   * which is precisely why the daemon cannot rely on that: it treats every
   * caller as untrusted, and the browser extension will speak this protocol
   * next.
   */
  it("refuses a fingerprint that is not 16 uppercase hex characters", async () => {
    for (const bad of ["../../../etc", "bbbbbbbbbbbbbbbb", "BBBB", "BBBBBBBBBBBBBBBB/x"]) {
      const put = await rawRequest({
        op: "put", cap, fingerprint: bad, mnemonic: MNEMONIC, ttl: 60,
      });
      expect(put["ok"]).toBe(false);
      expect(String(put["error"])).toContain("16 uppercase hex");
      const owner = await rawRequest({ op: "owner-mnemonic", cap, fingerprint: bad });
      expect(owner["ok"]).toBe(false);
      expect(JSON.stringify(owner)).not.toContain("abandon");
    }
  });

  it("refuses a well-formed fingerprint that does not belong to the seed", async () => {
    // Correct shape, wrong profile: this would unlock a vault the caller did
    // not name and file its audit records under the wrong fingerprint.
    const put = await rawRequest({
      op: "put", cap, fingerprint: SCRATCH_FP, mnemonic: MNEMONIC, ttl: 60,
    });
    expect(put["ok"]).toBe(false);
    expect(String(put["error"])).toContain("does not match");

    const owner = await rawRequest({ op: "owner-mnemonic", cap, fingerprint: SCRATCH_FP });
    expect(owner["ok"]).toBe(false);
    expect(JSON.stringify(owner)).not.toContain("abandon");
  });

  it("refuses an empty exec allowlist rather than making the token unrestricted", async () => {
    // Found by mutation testing. An empty allowlist used to be dropped, so a
    // caller computing an allowlist that came out empty — meaning "permit
    // nothing" — silently received a token permitting EVERY command. A
    // fail-open in the one field whose entire job is restriction.
    const r = await rawRequest({
      op: "token-issue",
      cap,
      fingerprint: FINGERPRINT,
      scopes: ["use"],
      ttl: 600,
      uses: 1,
      exec_allowlist: [],
    });
    expect(r["ok"]).toBe(false);
    expect(String(r["error"])).toContain("permit no command");
    expect(r["token"]).toBeUndefined();
  });

  it("still accepts an allowlist with entries", async () => {
    // The refusal above must be specific to the empty case; rejecting real
    // allowlists would push callers toward omitting the field entirely, which
    // is the permissive option.
    const r = await rawRequest({
      op: "token-issue",
      cap,
      fingerprint: FINGERPRINT,
      scopes: ["use"],
      ttl: 600,
      uses: 1,
      exec_allowlist: ["cat"],
    });
    expect(r["ok"]).toBe(true);
    expect((r["record"] as Record<string, unknown>)["exec_allowlist"]).toEqual(["cat"]);
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

describe("the owner capability", () => {
  it("refuses an empty or absent capability", async () => {
    // Mutation testing showed `!presented || !this.capability` could become
    // `&&` without any test noticing: the length comparison below it happens
    // to reject an empty string too, so the early return is redundant. It is
    // still the line that STATES the rule, and an empty credential being
    // refused is worth asserting outright rather than relying on a length
    // check further down to imply it.
    for (const cap of ["", undefined]) {
      const r = await rawRequest({
        op: "status",
        ...(cap !== undefined && { cap }),
      });
      expect(r["ok"]).toBe(false);
      expect(String(r["error"])).toMatch(/owner/i);
    }
  });

  it("refuses a capability of the right length but wrong content", async () => {
    const real = (await readFile(daemon.capabilityPath, "utf8")).trim();
    // Same length, so the length check cannot be what rejects it — this is
    // the constant-time comparison doing its job.
    const forged = "x".repeat(real.length);
    expect(forged).toHaveLength(real.length);
    const r = await rawRequest({ op: "status", cap: forged });
    expect(r["ok"]).toBe(false);
  });
});

// Shared by the boundary tests and the `put` guard tests below: both need
// a daemon on a clock they control.
const FROZEN = 1_800_000_000;
const TAG = "a".repeat(64);

async function daemonAt(now: () => number): Promise<{ d: AgentDaemon; sock: string }> {
  const dir = await mkdtemp(join(tmpdir(), "seedpass-expiry-"));
  // `put` writes an audit record, which needs the profile directory and an
  // index to serve from.
  const profile = join(dir, FINGERPRINT);
  await mkdir(profile, { recursive: true });
  await writeFile(
    join(profile, INDEX_FILENAME),
    await encryptV3(
      deriveIndexKeyBytes(MNEMONIC),
      utf8(JSON.stringify({ schema_version: 4, entries: {} })),
    ),
  );
  const sock = join(dir, "agent.sock");
  const d = new AgentDaemon(sock, 900, dir, now);
  await d.start();
  return { d, sock };
}

describe("token-issue validates before it mints", () => {
  // Everything here is reachable over the wire by a process that already
  // holds the owner socket, and none of it was asserted: the unlocked check
  // and both shape checks could be removed with the suite still green.
  let ownerCap: string;
  beforeAll(async () => {
    ownerCap = (await readFile(daemon.capabilityPath, "utf8")).trim();
  });

  it("refuses to mint a token for a profile it is not holding", async () => {
    // A token is an authorization to read a specific vault. Minting one for a
    // profile the agent never unlocked hands out authority nobody proved they
    // had — the seed being resident IS the proof.
    const other = generateFingerprint(mnemonics["zoo24"]!);
    const r = await rawRequest({
      op: "token-issue",
      cap: ownerCap,
      fingerprint: other,
      name: "for-a-vault-i-do-not-hold",
      scopes: ["read"],
      ttl: 600,
      uses: 1,
    });
    expect(r["ok"]).toBe(false);
    expect(String(r["error"])).toContain("not unlocked");
    expect(r["token"]).toBeUndefined();
  });

  it("refuses a scope it does not recognise, naming it", async () => {
    // A bogus scope grants nothing downstream — tokenAllows asks for read,
    // use or reveal by name — so dropping this check fails closed. But it
    // fails closed SILENTLY: the operator gets a token back, believes they
    // issued it, and only finds out when the job using it is denied. And a
    // near-miss is the likely case: "Read", "reveal " with a space, "write"
    // by analogy with other systems.
    const base = {
      op: "token-issue",
      cap: ownerCap,
      fingerprint: FINGERPRINT,
      name: "bad-scope",
      ttl: 600,
      uses: 1,
    };
    for (const scopes of [["admin"], ["read", "write"], ["Read"], ["reveal "]]) {
      const r = await rawRequest({ ...base, scopes });
      expect(r["ok"]).toBe(false);
      expect(String(r["error"])).toContain("unknown scopes");
      expect(r["token"]).toBeUndefined();
    }

    // All three real scopes together are fine, so this rejects the unknown
    // ones rather than anything about issuing a multi-scope token.
    const good = await rawRequest({ ...base, scopes: ["read", "use", "reveal"] });
    expect(good["ok"]).toBe(true);
  });

  it("refuses a bare string where an array is required", async () => {
    // `"read"` and `["read"]` are easy to confuse when hand-writing the
    // protocol, and the difference is not cosmetic: a string `kinds` turns
    // the exact kind match in tokenMaySee into String.includes, so a token
    // declared for one kind starts matching any kind whose name is a
    // substring of it. Refuse the shape rather than discovering it later.
    const base = {
      op: "token-issue",
      cap: ownerCap,
      fingerprint: FINGERPRINT,
      name: "wrong-shape",
      ttl: 600,
      uses: 1,
    };
    const badScopes = await rawRequest({ ...base, scopes: "read" });
    expect(badScopes["ok"]).toBe(false);
    expect(String(badScopes["error"])).toContain("scopes must be an array");
    expect(badScopes["token"]).toBeUndefined();

    const badKinds = await rawRequest({
      ...base,
      scopes: ["read"],
      kinds: "password",
    });
    expect(badKinds["ok"]).toBe(false);
    expect(String(badKinds["error"])).toContain("kinds must be an array");
    expect(badKinds["token"]).toBeUndefined();

    // The same request with both shapes correct does mint, so these tests
    // cannot pass by token-issue being broken outright.
    const good = await rawRequest({
      ...base,
      scopes: ["read"],
      kinds: ["password"],
    });
    expect(good["ok"]).toBe(true);
    expect(String(good["token"]).length).toBeGreaterThan(0);
  });
});

describe("the wire protocol refuses shapes, not just values", () => {
  it("insists a sink command is an array of strings", async () => {
    // The exec allowlist is checked with parseCommandSpec against the SAME
    // array that is later spawned, so a wrong shape cannot cause the check
    // and the spawn to disagree — every malformed shape fails closed. But
    // "fails closed" here means a TypeError or a nonsense command word, not
    // a refusal, and this daemon's stated posture is that every caller is
    // untrusted. Refuse the shape while it is still describable.
    for (const command of ["wc -c", 42, { cmd: "wc" }, ["wc", 5], [null]]) {
      const r = await rawRequest({
        op: "use-sink",
        fingerprint: FINGERPRINT,
        id: "1",
        sink: "exec",
        command,
      });
      expect(r["ok"]).toBe(false);
      expect(String(r["error"])).toContain("array of strings");
    }
  });
});

describe("starting a daemon over an existing socket", () => {
  it("refuses to replace a LIVE agent", async () => {
    // Without this check the second daemon deletes the socket and listens in
    // its place. The first keeps running — holding unlocked seeds, with an
    // expiry sweep nobody can reach and an audit log nobody is writing to.
    // Silently orphaning a process that holds seeds is worse than failing to
    // start, which is what makes this a refusal rather than a convenience.
    const { d, sock } = await daemonAt(() => FROZEN);
    try {
      const second = new AgentDaemon(sock, 900, join(sock, ".."), () => FROZEN);
      await expect(second.start()).rejects.toThrow(/already running/);

      // The original is still the one serving that socket.
      expect(await AgentClient.ping(sock)).toBe(true);
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 900);
      expect(await client.ownerMnemonic(FINGERPRINT)).toBe(MNEMONIC);
    } finally {
      await d.stop();
    }
  });

  it("cleans up a stale socket file rather than refusing forever", async () => {
    // The other half: a crashed agent leaves its socket behind, and treating
    // that as "already running" would make the agent unstartable until
    // someone deleted a file by hand.
    const dir = await mkdtemp(join(tmpdir(), "seedpass-stale-"));
    const sock = join(dir, "agent.sock");
    await writeFile(sock, "not a live socket");
    expect(await AgentClient.ping(sock)).toBe(false);

    const d = new AgentDaemon(sock, 900, dir, () => FROZEN);
    await d.start();
    try {
      expect(await AgentClient.ping(sock)).toBe(true);
    } finally {
      await d.stop();
    }
  });
});

describe("put refuses a half-supplied identity", () => {
  // `put` is the only door a seed comes through, and everything after it
  // trusts that both halves arrived. Mutation testing turned the `||` in its
  // guard into `&&`, which lets EITHER field be empty on its own -- and the
  // suite stayed green, because nothing asked what happens when one is blank.
  it("refuses an empty mnemonic under a well-formed fingerprint", async () => {
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      // The MESSAGE matters, not just the refusal: without this guard the
      // blank mnemonic falls through to the fingerprint comparison and
      // reports a mismatch, sending whoever reads it after the wrong field.
      await expect(client.put(FINGERPRINT, "", 900)).rejects.toThrow(/missing fields/);
      // And the refusal must be total: nothing resident afterwards.
      expect(await client.ownerMnemonic(FINGERPRINT)).toBeNull();
    } finally {
      await d.stop();
    }
  });

  it("names the malformed field when high-risk-unlock gets a bad fingerprint", async () => {
    // Disabling this guard entirely left the suite green: a malformed
    // fingerprint is never in `held`, so the "profile not unlocked" check
    // below refuses it anyway. The format check is still the one that should
    // answer -- "not unlocked" is a lie about a string that could never be a
    // profile in the first place, and it is the guard standing between a
    // caller-supplied string and the audit-log path join.
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 900);
      await expect(client.highRiskUnlock("../../etc", TAG, 300)).rejects.toThrow(
        /16 uppercase hex/,
      );
    } finally {
      await d.stop();
    }
  });

  it("refuses an empty fingerprint under a real seed", async () => {
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await expect(client.put("", MNEMONIC, 900)).rejects.toThrow(/missing fields/);
    } finally {
      await d.stop();
    }
  });
});

describe("expiry is denied AT the boundary, not after it", () => {
  /**
   * Mutation testing found `token.expires_at <= now` could become `<` with
   * every test still passing: the suite checked well before and well after
   * expiry, which cannot tell the two apart. "Expires at T" has to mean
   * denied AT T — otherwise a token is usable for one more request than it
   * claims, which is the wrong direction for a credential.
   *
   * The daemon takes an injectable clock so this can be pinned exactly
   * rather than raced against wall time.
   */


  it("stops handing out the high-risk tag at the exact instant it expires", async () => {
    // The most consequential of these: the tag IS the partition's encryption
    // key. A session that keeps answering past its expiry means the second
    // factor lapsed on paper only.
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 3600);
      await client.highRiskUnlock(FINGERPRINT, TAG, 60);

      clock = FROZEN + 59;
      expect(await client.highRiskTag(FINGERPRINT)).toBe(TAG);
      // `expires_at` is what tells a caller how long the second factor has
      // left, so assert the number and not just the flag: the client-side
      // null check that decodes it can invert with nothing noticing
      // otherwise, reporting 0 for a locked profile and null for a live one.
      expect(await client.highRiskStatus(FINGERPRINT)).toEqual({
        unlocked: true,
        expires_at: FROZEN + 60,
      });

      // Exactly at expiry the tag is gone. `<` would hand it over once more.
      clock = FROZEN + 60;
      expect(await client.highRiskTag(FINGERPRINT)).toBeNull();
      expect(await client.highRiskStatus(FINGERPRINT)).toEqual({
        unlocked: false,
        expires_at: null,
      });
    } finally {
      await d.stop();
    }
  });

  it("forgets a held seed at exactly its expiry, via the background sweep", async () => {
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 60);

      // The sweep runs on a real one-second timer, so each step waits for a
      // tick; only the daemon's notion of NOW is under test control.
      clock = FROZEN + 59;
      await new Promise((r) => setTimeout(r, 1200));
      expect(await client.ownerMnemonic(FINGERPRINT)).toBe(MNEMONIC);

      clock = FROZEN + 60;
      await new Promise((r) => setTimeout(r, 1200));
      expect(await client.ownerMnemonic(FINGERPRINT)).toBeNull();
    } finally {
      await d.stop();
    }
  });

  it("drops a high-risk session in the sweep even while the seed is still held", async () => {
    // The two lifetimes are independent: a high-risk grant is normally much
    // shorter than the seed's, and outliving it would silently extend the
    // second factor.
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 3600);
      await client.highRiskUnlock(FINGERPRINT, TAG, 60);

      clock = FROZEN + 60;
      await new Promise((r) => setTimeout(r, 1200));
      expect((await client.highRiskStatus(FINGERPRINT)).unlocked).toBe(false);
      // The seed itself is untouched — only the stronger grant lapsed.
      expect(await client.ownerMnemonic(FINGERPRINT)).toBe(MNEMONIC);
    } finally {
      await d.stop();
    }
  });

  it("denies a token at the exact instant it expires", async () => {
    let clock = FROZEN;
    const { d, sock } = await daemonAt(() => clock);
    try {
      const client = new AgentClient(sock);
      await client.put(FINGERPRINT, MNEMONIC, 900);
      const issued = await client.tokenIssue({
        fingerprint: FINGERPRINT,
        name: "boundary",
        scopes: ["read"],
        ttl: 60,
        uses: 5,
      });

      // One second before expiry: usable.
      clock = FROZEN + 59;
      await expect(client.vaultEntries(FINGERPRINT, issued.token)).resolves.toBeDefined();

      // EXACTLY at expiry: denied. This is the assertion `<` would fail.
      clock = FROZEN + 60;
      await expect(client.vaultEntries(FINGERPRINT, issued.token)).rejects.toThrow(
        /expired/,
      );
    } finally {
      await d.stop();
    }
  });
});
