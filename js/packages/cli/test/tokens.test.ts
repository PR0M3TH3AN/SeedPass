/**
 * Scoped-token enforcement tests: a token-holding process with NO mnemonic
 * anywhere in its environment gets exactly what its scopes grant — reads,
 * sink deliveries for permitted kinds/labels, nothing else — with every
 * decision landing in the tamper-evident audit log.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import { generateFingerprint } from "@seedpass/core";
import { buildProgram, AgentDaemon, agentSocketPath, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "token-test-pw";

let appDir: string;
let daemon: AgentDaemon;
let token: string;

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

const asOwner = { SEEDPASS_MNEMONIC: MNEMONIC };
const asTokenHolder = (t: string) => ({
  SEEDPASS_MNEMONIC: undefined,
  SEEDPASS_TOKEN: t,
});

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-tokens-"));
  process.env["SEEDPASS_AGENT_SOCK"] = join(appDir, "agent.sock");
  daemon = new AgentDaemon(agentSocketPath(appDir), 900, appDir);
  await daemon.start();

  await run({ ...asOwner, SEEDPASS_PASSWORD: PASSWORD }, "fingerprint", "add");
  await run(asOwner, "entry", "add", "key-value", "api-token", "k", "sinkable-secret");
  await run(asOwner, "entry", "add", "key-value", "internal-db", "k", "off-limits");
  await run(asOwner, "entry", "add", "password", "site-login", "--length", "16");
  await run({ SEEDPASS_MNEMONIC: undefined, SEEDPASS_PASSWORD: PASSWORD }, "vault", "unlock");
});

afterAll(async () => {
  await daemon.stop();
  delete process.env["SEEDPASS_AGENT_SOCK"];
});

describe("token issuance", () => {
  it("issues a scoped token, printed exactly once", async () => {
    const r = await run(
      {},
      "agent", "token-issue",
      "--name", "deploy-bot",
      "--scope", "read", "use",
      "--kind", "key_value",
      "--label-regex", "^api-",
      "--ttl", "600",
      "--uses", "2",
    );
    const issued = JSON.parse(r.stdout);
    token = issued.token;
    expect(token.length).toBeGreaterThan(20);
    expect(issued.record.scopes).toEqual(["read", "use"]);
    expect(issued.record).not.toHaveProperty("secret_hash");

    const list = JSON.parse((await run({}, "agent", "token-list")).stdout);
    expect(list[0].name).toBe("deploy-bot");
    expect(JSON.stringify(list)).not.toContain(token);
  });
});

/**
 * `label_regex` is a search, not a full match — in both implementations.
 * Python enforces it with `re.search` (cli/agent.py), so anchoring on the TS
 * side would mean the same token grants different access depending on which
 * implementation holds it, and would silently narrow every token already
 * issued. These tests pin the semantics so the surprise stays documented
 * rather than becoming an accidental behavior change later.
 */
describe("label_regex matches anywhere, matching Python's re.search", () => {
  it("an unanchored pattern reaches labels that merely contain it", async () => {
    await run(asOwner, "entry", "add", "key-value", "not-prod-db", "k", "adjacent-secret");
    await run(asOwner, "entry", "add", "key-value", "prod", "k", "intended-secret");

    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "substring-demo",
        "--scope", "read",
        "--kind", "key_value",
        "--label-regex", "prod",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    // The point of the test: BOTH are visible, not just the exact match.
    expect(rows.map((x) => x.label).sort()).toEqual(["not-prod-db", "prod"]);
  });

  it("anchoring the pattern is how an operator gets an exact match", async () => {
    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "anchored-demo",
        "--scope", "read",
        "--kind", "key_value",
        "--label-regex", "^prod$",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    expect(rows.map((x) => x.label)).toEqual(["prod"]);
  });

  it("reports the semantics in capabilities so automation can scope correctly", async () => {
    const caps = JSON.parse((await run({}, "capabilities")).stdout);
    expect(caps.tokens.label_regex_semantics).toContain("search");
    expect(caps.tokens.label_regex_semantics).toContain("^...$");
    // The exec allowlist's containment is likewise narrower than it reads:
    // it names a binary, not what that binary may be asked to do.
    expect(caps.tokens.exec_allowlist_semantics).toContain("command word only");
  });

  it("an uncompilable pattern denies rather than throwing", async () => {
    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "bad-regex",
        "--scope", "read",
        "--label-regex", "([unclosed",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    expect(rows).toEqual([]);
  });
});

describe("token-mode access (no mnemonic anywhere)", () => {
  it("lists only the entries the token may act on, with no secret values", async () => {
    const r = await run(asTokenHolder(token), "entry", "list");
    const rows = JSON.parse(r.stdout) as { label: string }[];
    // Scoped to kind key_value and labels matching ^api-, so the password
    // entry and the non-matching key_value are not even disclosed.
    expect(rows.map((x) => x.label)).toEqual(["api-token"]);
    expect(r.stdout).not.toContain("sinkable-secret");
    expect(r.stdout).not.toContain("off-limits");
  });

  it("delivers a permitted secret to a sink", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-tok-sink-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s' "$SEEDPASS_SECRET" > "${capture}"\n`, {
      mode: 0o755,
    });
    const r = await run(asTokenHolder(token), "use", "api-token", "--exec", script);
    expect(JSON.parse(r.stdout).exitCode).toBe(0);
    expect(await readFile(capture, "utf8")).toBe("sinkable-secret");
    expect(r.stdout).not.toContain("sinkable-secret");
  });

  it("denies reveal (scope), wrong kind, and non-matching label", async () => {
    const reveal = await run(asTokenHolder(token), "entry", "reveal", "api-token");
    expect(String((reveal.error as Error).message)).toContain("scope 'reveal' not granted");

    // Entries outside the token's constraints are not resolvable at all —
    // the agent never returned them, so their existence is not disclosed.
    const wrongKind = await run(asTokenHolder(token), "use", "site-login", "--stdin-to", "cat");
    expect(String((wrongKind.error as Error).message)).toContain("no entry matches");

    const wrongLabel = await run(asTokenHolder(token), "use", "internal-db", "--stdin-to", "cat");
    expect(String((wrongLabel.error as Error).message)).toContain("no entry matches");

    // Addressing a forbidden entry by id still fails, in the agent
    const byId = await run(asTokenHolder(token), "use", "sp://entry/2", "--stdin-to", "cat");
    expect(String((byId.error as Error).message)).toMatch(/no entry|denied/);
  });

  it("exhausts after the allotted uses", async () => {
    // Use #2 of 2 (use #1 was the sink delivery above; denials don't consume)
    const second = await run(asTokenHolder(token), "use", "api-token", "--stdin-to", "cat");
    expect(second.error).toBeUndefined();
    const third = await run(asTokenHolder(token), "use", "api-token", "--stdin-to", "cat");
    expect(String((third.error as Error).message)).toContain("token exhausted");
  });

  it("revocation cuts off reads too", async () => {
    const list = JSON.parse((await run({}, "agent", "token-list")).stdout);
    await run({}, "agent", "token-revoke", list[0].id);
    const denied = await run(asTokenHolder(token), "entry", "list");
    expect(String((denied.error as Error).message)).toContain("token revoked");
  });

  it("token mode cannot provision or modify", async () => {
    const r = await run(asTokenHolder(token), "entry", "add", "key-value", "x", "k", "v");
    expect(r.error).toBeTruthy();
  });
});

describe("audit chain", () => {
  it("recorded the whole story and verifies", async () => {
    const r = await run(asOwner, "agent", "audit-verify");
    const summary = JSON.parse(r.stdout);
    expect(summary.verified).toBe(true);
    expect(summary.records).toBeGreaterThanOrEqual(6);

    const tail = JSON.parse((await run(asOwner, "agent", "audit-tail", "-n", "50")).stdout) as {
      event: string;
      details: Record<string, unknown>;
    }[];
    const events = tail.map((r) => r.event);
    expect(events).toContain("token_issued");
    expect(events).toContain("secret_delivered");
    expect(events).toContain("access_denied");
    expect(events).toContain("token_revoked");
    const denial = tail.find((r) => r.event === "access_denied")!;
    expect(String(denial.details["reason"])).toBeTruthy();
    // Secrets never appear in the audit log
    expect(JSON.stringify(tail)).not.toContain("sinkable-secret");
  });

  it("detects tampering", async () => {
    const path = join(appDir, FINGERPRINT, "audit.log");
    await appendFile(path, JSON.stringify({ timestamp: "x", event: "forged", details: {}, sig: "00" }) + "\n");
    const r = await run(asOwner, "agent", "audit-verify");
    expect(String((r.error as Error).message)).toContain("audit chain broken");
  });
});
